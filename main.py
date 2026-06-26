import os
import json
import re
import boto3
import subprocess
import shutil
import git
import time
import logging
import itertools
import threading
from typing import TypedDict, List, Literal, Optional

from langgraph.graph import StateGraph, START, END
from langchain_groq import ChatGroq
from langchain_cerebras import ChatCerebras
from langchain_core.messages import SystemMessage, HumanMessage
from dotenv import load_dotenv

import poc_runner
import precondition as precond
import rule_book

load_dotenv()

# ============================================================
# LOGGING
# ============================================================
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

S3_BUCKET = os.getenv("S3_BUCKET", "solidity-guard-vault")
s3 = boto3.client("s3")

# ============================================================
# API KEY HAVUZU (GROQ kaldırıldı - tamamen Cerebras + opsiyonel Groq fallback iskeleti bırakıldı)
# ============================================================
# NOT: Konuşmada GROQ key'lerin tükendiğini ve kaldırıldığını belirttin.
# Bu yüzden varsayılan davranış artık SADECE Cerebras. Ama yarın yeniden
# Groq key eklersen kod otomatik onu da devreye alır (geriye dönük uyumlu).
GROQ_KEYS = sorted([v for k, v in os.environ.items() if k.startswith("GROQ_API_KEY_") and v])
CEREBRAS_KEYS = sorted([v for k, v in os.environ.items() if k.startswith("CEREBRAS_API_KEY_") and v])

if not GROQ_KEYS and not CEREBRAS_KEYS:
    raise ValueError("Hiç API key bulunamadı! En az bir CEREBRAS_API_KEY_x gerekli.")

logger.info(f"Groq key sayısı: {len(GROQ_KEYS)} | Cerebras key sayısı: {len(CEREBRAS_KEYS)}")

groq_cycle = itertools.cycle(GROQ_KEYS) if GROQ_KEYS else None
cerebras_cycle = itertools.cycle(CEREBRAS_KEYS) if CEREBRAS_KEYS else None

_exhausted_groq_keys = set()
_exhausted_lock = threading.Lock()


def get_llm(temperature: float = 0, task_type: str = "triage"):
    """Cerebras öncelikli (GROQ artık yok), ama GROQ_API_KEY_x eklenirse otomatik devreye girer."""
    available_groq = [k for k in GROQ_KEYS if k not in _exhausted_groq_keys]

    if available_groq:
        key = next(groq_cycle)
        if key in _exhausted_groq_keys:
            key = available_groq[0]
        logger.info(f"[LLM] Provider: groq | Model: llama-3.3-70b-versatile | Görev: {task_type} | temp={temperature}")
        return ChatGroq(
            model="llama-3.3-70b-versatile",
            groq_api_key=key,
            temperature=temperature,
            max_tokens=4096,
            max_retries=0,
        )

    if not CEREBRAS_KEYS:
        raise RuntimeError("Tüm API keyleri tükendi!")
    key = next(cerebras_cycle)
    logger.info(f"[LLM] Provider: cerebras | Model: gpt-oss-120b | Görev: {task_type} | temp={temperature}")
    return ChatCerebras(
        model="gpt-oss-120b",
        cerebras_api_key=key,
        temperature=temperature,
        max_tokens=4096,
    )


def llm_text(prompt: str, temperature: float = 0.0, task_type: str = "helper") -> str:
    """poc_runner / precondition / rule_book modüllerine verilen basit callback."""
    llm = get_llm(temperature=temperature, task_type=task_type)
    return llm.invoke(prompt).content


# ============================================================
# STATE
# ============================================================
class AgentState(TypedDict):
    repo_url: str
    repo_local_path: str
    contract_code: str
    slither_report: str

    theorist_claim: str
    exploit_chain: str
    proofs: str

    precondition_result: dict
    precondition_rendered: str

    poc_status: str          # SUCCESS | FAIL | UNAVAILABLE | INCONCLUSIVE | NOT_ATTEMPTED
    poc_state_diff: str
    poc_error_summary: str
    poc_attempts: int

    triager1_verdict: str
    triager2_verdict: str
    impact_assessment: str
    t2_dialogue: List[dict]

    last_rejection_context: str
    final_status: str
    loop_count: int
    poc_retry_count: int

    run_id: str


MAX_LOOPS = 10
MAX_POC_RETRIES = 2  # theorist'e PoC hatasını düzeltme şansı - 1-2 retry (karar: 2)


# ==================== YARDIMCI FONKSİYONLAR ====================
def fetch_s3_context(prefix: str) -> str:
    try:
        objs = s3.list_objects_v2(Bucket=S3_BUCKET, Prefix=prefix).get("Contents", [])[:5]
        out = []
        for o in objs:
            body = s3.get_object(Bucket=S3_BUCKET, Key=o["Key"])["Body"].read().decode("utf-8", "ignore")
            out.append(f"File: {o['Key']}\n{body[:800]}...")
        return "\n\n".join(out) if out else "(No previous context found)"
    except Exception as e:
        logger.warning(f"S3 context fetch hatası (prefix={prefix}): {e}")
        return "(S3 Context Unavailable)"


def _safe_json(text: str) -> dict:
    try:
        clean = re.sub(r"```json\s*|```", "", text.strip())
        start = clean.find("{")
        end = clean.rfind("}") + 1
        if start != -1 and end > start:
            return json.loads(clean[start:end])
        return json.loads(clean)
    except Exception:
        return {}


def load_contracts_from_s3() -> str:
    logger.info("S3 contracts/ klasöründen kontratlar yükleniyor...")
    try:
        objs = s3.list_objects_v2(Bucket=S3_BUCKET, Prefix="contracts/").get("Contents", [])
        sol_files = [o for o in objs if o["Key"].endswith(".sol")]
        if not sol_files:
            logger.error("S3 contracts/ klasöründe hiç .sol dosyası bulunamadı!")
            return ""
        combined_code = ""
        for o in sol_files:
            key = o["Key"]
            body = s3.get_object(Bucket=S3_BUCKET, Key=key)["Body"].read().decode("utf-8", "ignore")
            filename = key.split("/")[-1]
            combined_code += f"\n--- {filename} ---\n{body}\n"
            logger.info(f" Yüklendi: {key}")
        logger.info(f"Toplam {len(sol_files)} kontrat S3'ten yüklendi.")
        return combined_code
    except Exception as e:
        logger.error(f"S3'ten kontrat yükleme hatası: {e}")
        return ""


def clone_and_upload_repo(repo_url: str):
    local_path = "./target_repo"
    if os.path.exists(local_path):
        shutil.rmtree(local_path)
    logger.info(f"Repo klonlanıyor: {repo_url}")
    git.Repo.clone_from(repo_url, local_path)
    logger.info("Repo S3 'contracts/' klasörüne yükleniyor...")
    for root, _, files in os.walk(local_path):
        for file in files:
            if file.endswith(".sol"):
                file_path = os.path.join(root, file)
                s3_key = f"contracts/{os.path.relpath(file_path, local_path)}"
                try:
                    with open(file_path, "rb") as f:
                        s3.put_object(Bucket=S3_BUCKET, Key=s3_key, Body=f)
                except Exception as e:
                    logger.warning(f"S3 yükleme hatası ({s3_key}): {e}")
    combined_code = ""
    for root, _, files in os.walk(local_path):
        for file in files:
            if file.endswith(".sol"):
                with open(os.path.join(root, file), "r", encoding="utf-8") as f:
                    combined_code += f"\n--- {file} ---\n{f.read()}\n"
    return combined_code, local_path


def get_next_bug_id(prefix: str) -> int:
    try:
        objs = s3.list_objects_v2(Bucket=S3_BUCKET, Prefix=prefix).get("Contents", [])
        existing_ids = set()
        for o in objs:
            filename = o["Key"].split("/")[-1]
            name = filename.replace(".md", "").replace(".json", "")
            parts = name.split(".")
            for part in parts:
                if part.isdigit():
                    existing_ids.add(int(part))
                    break
        candidate = 0
        while candidate in existing_ids:
            candidate += 1
        return candidate
    except Exception as e:
        logger.warning(f"Bug ID hesaplama hatası: {e}")
        return int(time.time())


def extract_severity(impact_text: str) -> str:
    text = impact_text.upper()
    match = re.search(r'\[SEVERITY:\s*(CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL|INFO)\]', text)
    if match:
        raw = match.group(1)
    else:
        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]:
            if level in text:
                raw = level
                break
        else:
            raw = "UNKNOWN"
    mapping = {
        "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
        "LOW": "low", "INFORMATIONAL": "info", "INFO": "info", "UNKNOWN": "unknown"
    }
    return mapping.get(raw, "unknown")


def run_slither_analysis(local_path: str) -> str:
    logger.info(f"[Slither] Repo taranıyor: {local_path}")
    try:
        result = subprocess.run(
            ["slither", local_path, "--json", "-"],
            capture_output=True, text=True, timeout=300
        )
        if result.stdout.strip():
            return f"Slither Findings (Full Repo):\n{result.stdout[:4000]}"
        return "Slither Status: Clean"
    except subprocess.TimeoutExpired:
        logger.warning("Slither zaman aşımına uğradı.")
        return "Slither Status: Timeout"
    except FileNotFoundError:
        logger.error("Slither kurulu değil!")
        return "Slither Status: Not Installed"
    except Exception as e:
        logger.error(f"Slither hatası: {e}")
        return f"Slither error: {e}"


# ==================== NODES ====================
def theorist_node(state: AgentState):
    loop_num = state.get("loop_count", 0) + 1
    logger.info(f"[Theorist] Analiz Başlıyor (Deneme #{loop_num})...")
    llm = get_llm(temperature=0.35, task_type="heavy")
    rag_context = fetch_s3_context("knowledge-base/")

    # ESKİ: ham self-learning rejection metinleri.
    # YENİ: distile edilmiş kural kitabı (rule_book.py) - genel pattern, ham tekrar değil.
    rules_context = rule_book.render_rule_book_for_prompt(state["repo_url"])

    slither_data = state.get("slither_report") or run_slither_analysis(state["repo_local_path"])

    rejection_prompt = ""
    if state.get("last_rejection_context"):
        rejection_prompt = (
            f"\n\n⚠️ BU TURDA REDDEDİLDİN:\n{state['last_rejection_context']}\n"
            f"Farklı bir açıdan yaklaş, aynı iddiayı tekrarlama!"
        )

    # PoC retry durumu: theorist'e derleme/çalışma hatasını göster, exploit_chain'i
    # o hataya göre düzeltmesini iste (precondition/claim aynı kalabilir, sadece
    # teknik yürütülebilirlik düzeltilsin).
    poc_retry_prompt = ""
    if state.get("poc_error_summary") and state.get("poc_retry_count", 0) > 0:
        poc_retry_prompt = (
            f"\n\n🔧 PoC ÇALIŞTIRMA HATASI (Deneme {state.get('poc_retry_count')}/{MAX_POC_RETRIES}):\n"
            f"{state['poc_error_summary'][:1200]}\n"
            f"Bu hata PoC YAZIMINDAN kaynaklanıyor olabilir, exploit fikrinin kendisi yanlış olmak "
            f"zorunda değil. exploit_chain'i bu teknik hatayı dikkate alarak, daha kesin ve "
            f"yürütülebilir adımlarla yeniden yaz (örn. doğru fonksiyon imzası, doğru parametre sırası, "
            f"gerçekçi başlangıç state'i)."
        )

    prompt = f"""Sen üst düzey bir Web3 Güvenlik Denetçisisin. Bu çalışma savunma amaçlıdır.
KNOWLEDGE-BASE (geçmiş audit raporları):
{rag_context}

{rules_context}

SLITHER RAPORU: {slither_data}
KOD:
{state['contract_code'][:18000]}
{rejection_prompt}
{poc_retry_prompt}
En kritik zafiyeti bul. Çıktını **sadece saf JSON** olarak ver:
{{
  "claim": "Zafiyetin kısa ve teknik tanımı",
  "exploit_chain": "Adım adım exploit senaryosu",
  "proofs": "Kod referansları ve kanıtlar"
}}"""
    resp = llm.invoke(prompt).content
    data = _safe_json(resp)
    return {
        "slither_report": slither_data,
        "theorist_claim": data.get("claim", "İddia ayrıştırılamadı."),
        "exploit_chain": data.get("exploit_chain", "Zincir ayrıştırılamadı."),
        "proofs": data.get("proofs", resp),
        # Bir önceki PoC hata bilgisini bu node tükettiği için temizle
        "poc_error_summary": "",
    }


def precondition_node(state: AgentState):
    """
    YENİ NODE: theorist'ten sonra, PoC'tan/triager'dan ÖNCE çalışır.
    Exploit chain'i atomik önkoşullara ayırır, her birini kod üzerinde
    bağımsız sorgular. "Mantıklı mı" yerine "bu adım kodda gerçekten
    mümkün mü" sorusu sorulur.
    """
    logger.info("[Precondition Extractor] Exploit zinciri ayrıştırılıyor...")
    result = precond.extract_preconditions(
        contract_code=state["contract_code"],
        theorist_claim=state["theorist_claim"],
        exploit_chain=state["exploit_chain"],
        llm_invoke_fn=lambda p: llm_text(p, temperature=0.0, task_type="precondition"),
    )
    rendered = precond.render_preconditions_for_prompt(result)
    logger.info(f"[Precondition Extractor] overall_plausible={result.get('overall_plausible')}")
    return {
        "precondition_result": result,
        "precondition_rendered": rendered,
    }


def route_precondition(state: AgentState) -> Literal["poc_builder", "triager1", "loop_counter"]:
    """
    Eğer önkoşullardan biri açıkça IMPLAUSIBLE ise (kodun kendisiyle çelişiyorsa),
    PoC'a/triager'a hiç gitmeden direkt reddet - bu hem token tasarrufu hem de
    "açıkça yanlış olanı bile triager'a sorup onay riski yaratma" ilkesi.
    Aksi halde (PLAUSIBLE veya UNCERTAIN) PoC denemesine geç.
    """
    result = state.get("precondition_result", {})
    overall = result.get("overall_plausible")

    if overall is False:
        logger.info(f"{RED}[Route] Precondition açıkça IMPLAUSIBLE → direkt red, PoC/triager atlanıyor{RESET}")
        return "loop_counter"

    if poc_runner.check_forge_available():
        return "poc_builder"

    logger.info(f"{YELLOW}[Route] forge mevcut değil → metin-bazlı triager zincirine düşülüyor{RESET}")
    return "triager1"


def poc_builder_node(state: AgentState):
    """
    YENİ NODE: Gerçek mainnet fork üzerinde PoC çalıştırır.
    KARAR: PoC başarılıysa (state-diff kanıtlı) → direkt ACCEPTED yolu (impact_assessor'a gider).
           PoC başarısızsa → 1-2 retry (theorist exploit_chain'i düzeltir).
           Retry'lar da tükenirse → eski metin-bazlı triager zincirine düşülür (belirsiz sayılır,
           "exploit yok" anlamına gelmez).
    """
    logger.info("[PoC Builder] Mainnet fork üzerinde PoC çalıştırılıyor...")
    result = poc_runner.run_poc(
        repo_local_path=state["repo_local_path"],
        contract_code=state["contract_code"],
        theorist_claim=state["theorist_claim"],
        exploit_chain=state["exploit_chain"],
        proofs=state["proofs"],
        preconditions=state.get("precondition_rendered", ""),
        llm_invoke_fn=lambda p: llm_text(p, temperature=0.1, task_type="poc_codegen"),
        run_workspace=f"./poc_workspace_{state.get('run_id', 'default')}",
    )

    if result.status == "SUCCESS":
        logger.info(f"{GREEN}[PoC Builder] ✅ PoC BAŞARILI - state-diff kanıtlandı{RESET}")
    elif result.status == "FAIL":
        logger.info(f"{RED}[PoC Builder] ❌ PoC başarısız (derleme/test hatası){RESET}")
    else:
        logger.info(f"{YELLOW}[PoC Builder] ⚠️ PoC sonucu belirsiz: {result.status}{RESET}")

    return {
        "poc_status": result.status,
        "poc_state_diff": result.state_diff_proof,
        "poc_error_summary": result.error_summary,
        "poc_attempts": state.get("poc_attempts", 0) + 1,
    }


def route_poc(state: AgentState) -> Literal["impact_assessor", "poc_retry", "triager1"]:
    status = state.get("poc_status", "")

    if status == "SUCCESS":
        # KARAR: mainnet forkta çalışıyorsa iş bitmiştir, accepted yoluna gir.
        logger.info(f"{GREEN}[Route] PoC SUCCESS → direkt Impact Assessment (triager atlanıyor){RESET}")
        return "impact_assessor"

    if status == "FAIL":
        retry_count = state.get("poc_retry_count", 0)
        if retry_count < MAX_POC_RETRIES:
            logger.info(f"{YELLOW}[Route] PoC FAIL → theorist'e retry hakkı veriliyor ({retry_count + 1}/{MAX_POC_RETRIES}){RESET}")
            return "poc_retry"
        logger.info(f"{YELLOW}[Route] PoC retry hakları tükendi → belirsiz, metin-bazlı triager'a düşülüyor{RESET}")
        return "triager1"

    # UNAVAILABLE / INCONCLUSIVE → bizden kaynaklı olabilir, "exploit yok" denemez.
    logger.info(f"{YELLOW}[Route] PoC {status} (belirsiz) → metin-bazlı triager'a düşülüyor{RESET}")
    return "triager1"


def poc_retry_node(state: AgentState):
    """PoC retry sayacını artırıp theorist'e geri döner (exploit_chain düzeltme turu)."""
    new_count = state.get("poc_retry_count", 0) + 1
    logger.info(f"[PoC Retry] Theorist'e dönülüyor, retry #{new_count}")
    return {"poc_retry_count": new_count}


def hard_triager1_node(state: AgentState):
    """
    FELSEFİ DEĞİŞİKLİK: Bu node artık sadece "claim + exploit_chain mantıklı mı"
    sormuyor. precondition_rendered (atomik önkoşul analizi) ve varsa
    poc_error_summary (PoC neden çalışmadı) de prompt'a ekleniyor. Bu, triager'ın
    "hikayeyi onayla" modundan "spesifik teknik iddiaları çürütmeye çalış" moduna
    geçmesini sağlamak için.
    """
    logger.info("[Triager 1] Denetim yapılıyor (precondition-aware)...")
    llm = get_llm(temperature=0.0, task_type="triage")

    poc_context = ""
    if state.get("poc_status") in ("FAIL", "INCONCLUSIVE", "UNAVAILABLE"):
        poc_context = (
            f"\n\nNOT: Bu iddia için otomatik PoC denemesi yapıldı, sonuç: {state.get('poc_status')}.\n"
            f"PoC'un çalışmaması TEK BAŞINA bu iddianın yanlış olduğu anlamına gelmez - "
            f"PoC altyapısından kaynaklı olabilir. Yine de PoC hata detayını teknik bir sinyal "
            f"olarak değerlendir:\n{state.get('poc_error_summary', '')[:800]}"
        )

    prompt = f"""Sen titiz bir Lead Auditor'sün. Görevin BU İDDİAYI ÇÜRÜTMEYE ÇALIŞMAK - sana
sunulan hikayenin tutarlı görünmesi yeterli değil, her adımın kodun kendisinde GERÇEKTEN
mümkün olduğunu doğrulaman gerekiyor.

KOD: {state['contract_code'][:15000]}
SLITHER: {state.get('slither_report')}
İDDİA: {state['theorist_claim']}
EXPLOIT ZİNCİRİ: {state['exploit_chain']}

ATOMİK ÖNKOŞUL ANALİZİ (bağımsız bir analiz adımından geldi, bunu referans al ama
kendi başına da kontrol et):
{state.get('precondition_rendered', '(önkoşul analizi mevcut değil)')}
{poc_context}

GÖREV: Önkoşul analizindeki her IMPLAUSIBLE veya UNCERTAIN işaretli adımı özellikle
sorgula. Eğer tek bir adım bile kodun gerçek mantığıyla çelişiyorsa REDDET.
[ACCEPTED] veya [REJECTED] ile başla ve teknik gerekçeni detaylı açıkla."""
    resp = llm.invoke(prompt).content
    return {"triager1_verdict": resp}


def blind_triager2_node(state: AgentState):
    logger.info("[Triager 2 / BLIND] Kanıt zincirini değerlendiriyor...")
    blind_llm = get_llm(temperature=0.0, task_type="triage")
    helper_llm = get_llm(temperature=0.2, task_type="heavy")
    dialogue = state.get("t2_dialogue", [])
    current_proof = state.get("proofs", "")
    blind_system = SystemMessage(content=(
        "Sen koda erişimi olmayan acımasız bir Zero-Context Triager'sın. "
        "Cevabını [ACCEPTED], [REJECTED] veya [NEED_PROOF] ile başlat."
    ))
    MAX_TURNS = 3
    verdict = "[REJECTED] Yetersiz kanıt."
    for turn in range(MAX_TURNS):
        review = blind_llm.invoke([
            blind_system,
            HumanMessage(content=f"SUNULAN KANITLAR:\n{current_proof}\n\nBu zincir mantıksal olarak tutarlı mı?")
        ]).content
        dialogue.append({"blind_query": review})
        head = review.strip().upper()
        if "[ACCEPTED]" in head or "[REJECTED]" in head:
            verdict = review
            break
        elif "[NEED_PROOF]" in head:
            helper_answer = helper_llm.invoke(
                f"KOD: {state['contract_code'][:10000]}\n\nKör triager'ın istediği ek kanıt: {review}\nKanıt üret."
            ).content
            dialogue.append({"helper_response": helper_answer})
            current_proof += f"\n\n--- EK KANIT #{turn+1} ---\n{helper_answer}"
    return {
        "triager2_verdict": verdict,
        "t2_dialogue": dialogue,
        "proofs": current_proof
    }


def route_triager1(state: AgentState) -> Literal["triager2", "loop_counter", "end"]:
    if state.get("loop_count", 0) >= MAX_LOOPS:
        logger.info("MAX_LOOPS sınırına ulaşıldı. Sonlandırılıyor.")
        return "end"
    verdict = state.get("triager1_verdict", "").strip().upper()
    if "[ACCEPTED]" in verdict:
        logger.info(f"{GREEN}✅ Triager1 ONAYLADI{RESET}")
        return "triager2"
    logger.info(f"{RED}❌ Triager1 REDDETTİ{RESET}")
    return "loop_counter"


def route_triager2(state: AgentState) -> Literal["impact_assessor", "loop_counter", "end"]:
    if state.get("loop_count", 0) >= MAX_LOOPS:
        logger.info("MAX_LOOPS sınırına ulaşıldı. Sonlandırılıyor.")
        return "end"
    verdict = state.get("triager2_verdict", "").strip().upper()
    if "[ACCEPTED]" in verdict:
        logger.info(f"{GREEN}✅ Triager2 ONAYLADI -> Impact Assessment{RESET}")
        return "impact_assessor"
    logger.info(f"{RED}❌ Triager2 REDDETTİ{RESET}")
    return "loop_counter"


def impact_assessor_node(state: AgentState):
    logger.info("[Impact Assessor] Gerçek dünya riskini değerlendiriyor...")
    llm = get_llm(temperature=0.2, task_type="heavy")

    poc_evidence = ""
    if state.get("poc_status") == "SUCCESS":
        poc_evidence = f"\n\n✅ MAINNET FORK POC KANITI (state-diff ile doğrulandı):\n{state.get('poc_state_diff', '')}"

    prompt = f"""Sen Immunefi ve Cantina'da 5+ yıldır triaging yapan Senior Security Researcher'sün.
Teknik bulgu:
Claim: {state.get('theorist_claim')}
Exploit Chain: {state.get('exploit_chain')}
Proofs: {state.get('proofs')}
{poc_evidence}
Bu bulguyu gerçek dünya açısından değerlendir:
- Bu gerçekten sömürülebilir bir zafiyet mi?
- Kullanıcının özel hata yapması mı gerekiyor?
- Severity seviyesi nedir? (Critical / High / Medium / Low / Informational)
Cevabına **[SEVERITY: Critical/High/Medium/Low/Informational]** ile başla."""
    resp = llm.invoke(prompt).content
    return {"impact_assessment": resp}


def final_node(state: AgentState):
    # Kabul kriteri: PoC SUCCESS (mainnet fork + state-diff kanıtı) İLE YA DA
    # PoC mevcut değilken eski metin-bazlı triager2 ACCEPTED verdiyse.
    poc_success = state.get("poc_status") == "SUCCESS"
    triager_success = "[ACCEPTED]" in state.get("triager2_verdict", "").strip().upper()
    is_success = poc_success or triager_success

    severity = extract_severity(state.get("impact_assessment", ""))
    if is_success:
        bug_id = get_next_bug_id("self-learning/verified/")
    else:
        bug_id = get_next_bug_id("self-learning/rejections/")
    filename = f"context.{bug_id}.{severity}.md"

    poc_section = ""
    if state.get("poc_status"):
        poc_section = f"""
**PoC Status:** {state.get('poc_status')}
**PoC State-Diff Kanıtı:** {state.get('poc_state_diff', 'N/A')}
"""

    context_content = f"""# VULNERABILITY CONTEXT REPORT
ID: {bug_id}
STATUS: {'ACCEPTED' if is_success else 'REJECTED'}
SEVERITY: {severity.upper()}
KABUL YÖNTEMİ: {'Mainnet Fork PoC (state-diff)' if poc_success else 'Metin-bazlı Triager Zinciri'}
**Claim:** {state.get('theorist_claim')}
**Exploit Chain:** {state.get('exploit_chain')}
**Proofs:** {state.get('proofs')}
**Slither:** {state.get('slither_report', 'N/A')}
**Impact Assessment:** {state.get('impact_assessment', 'N/A')}
{poc_section}
"""
    maya_content = f"""# VULNERABILITY MAYA (SOYUT GEREKSİNİMLER)
ID: {bug_id} | SEVERITY: {severity.upper()}
EXPLOIT ZİNCİRİ:
{state.get('exploit_chain')}
Bu exploit'in gerçek dünyada gerçekleşmesi için gereken koşulları değerlendir."""

    try:
        if is_success:
            s3.put_object(Bucket=S3_BUCKET, Key=f"self-learning/verified/{filename}", Body=context_content.encode("utf-8"))
            s3.put_object(Bucket=S3_BUCKET, Key=f"verified_reports/{filename}", Body=context_content.encode("utf-8"))
            s3.put_object(Bucket=S3_BUCKET, Key=f"maya/maya.{bug_id}.{severity}.md", Body=maya_content.encode("utf-8"))
            logger.info(f"{GREEN}✅ KABUL EDİLDİ → {filename} (Severity: {severity.upper()}, Yöntem: {'PoC' if poc_success else 'Triager'}){RESET}")
        else:
            s3.put_object(Bucket=S3_BUCKET, Key=f"self-learning/rejections/{filename}", Body=context_content.encode("utf-8"))
            logger.info(f"{RED}⚠️ REDDEDİLDİ → {filename}{RESET}")
    except Exception as e:
        logger.error(f"S3 kayıt hatası: {e}")


def loop_counter_node(state: AgentState):
    """
    YENİ: Artık ham rejection metnini self-learning/rejections'a yazmakla
    YETİNMİYOR. rule_book.add_rejection_and_distill() ile reddi genel bir
    kurala indirip kural kitabına ekliyor (karar: LLM ile otomatik distillation).
    """
    current_loop = state.get("loop_count", 0)
    reason = "Triager reddi"

    precond_result = state.get("precondition_result", {})
    if precond_result.get("overall_plausible") is False:
        reason = f"Precondition reddi: {precond_result.get('weakest_link', '')[:300]}"
    elif state.get("triager1_verdict") and "[ACCEPTED]" not in state.get("triager1_verdict", "").upper():
        reason = f"Triager1: {state['triager1_verdict'][:300]}"
    elif state.get("triager2_verdict") and "[ACCEPTED]" not in state.get("triager2_verdict", "").upper():
        reason = f"Triager2: {state['triager2_verdict'][:300]}"

    logger.info(f"{RED}[Loop Counter] Reddedildi → Döngü #{current_loop + 1}{RESET}")

    # --- Distile edilmiş kural kitabına ekleme ---
    try:
        rule_book.add_rejection_and_distill(
            repo_label=state["repo_url"],
            theorist_claim=state.get("theorist_claim", ""),
            exploit_chain=state.get("exploit_chain", ""),
            rejection_reason=reason,
            llm_invoke_fn=lambda p: llm_text(p, temperature=0.0, task_type="rule_distill"),
        )
    except Exception as e:
        logger.warning(f"[Loop Counter] Rule book güncelleme hatası: {e}")

    # --- Ham log (debugging / denetim amaçlı, S3'te ayrıca kalsın) ---
    try:
        rejection_id = get_next_bug_id("self-learning/rejections/")
        rejection_content = f"""# REJECTED ATTEMPT
ID: {rejection_id}
LOOP: {current_loop}
RED GEREKÇESİ: {reason}
İDDİA: {state.get('theorist_claim', '(yok)')}
EXPLOIT: {state.get('exploit_chain', '(yok)')[:300]}
POC STATUS: {state.get('poc_status', 'N/A')}
"""
        s3.put_object(
            Bucket=S3_BUCKET,
            Key=f"self-learning/rejections/context.{rejection_id}.rejected.md",
            Body=rejection_content.encode("utf-8")
        )
        logger.info(f"Red kaydedildi → self-learning/rejections/context.{rejection_id}.rejected.md")
    except Exception as e:
        logger.warning(f"Rejection log S3 hatası: {e}")

    return {
        "loop_count": current_loop + 1,
        "last_rejection_context": reason,
        "theorist_claim": "",
        "exploit_chain": "",
        "proofs": "",
        "precondition_result": {},
        "precondition_rendered": "",
        "poc_status": "",
        "poc_state_diff": "",
        "poc_error_summary": "",
        "poc_retry_count": 0,
        "triager1_verdict": "",
        "triager2_verdict": "",
        "t2_dialogue": []
    }


# ==================== GRAPH ====================
workflow = StateGraph(AgentState)
workflow.add_node("theorist", theorist_node)
workflow.add_node("precondition", precondition_node)
workflow.add_node("poc_builder", poc_builder_node)
workflow.add_node("poc_retry", poc_retry_node)
workflow.add_node("triager1", hard_triager1_node)
workflow.add_node("triager2", blind_triager2_node)
workflow.add_node("impact_assessor", impact_assessor_node)
workflow.add_node("final", final_node)
workflow.add_node("loop_counter", loop_counter_node)

workflow.add_edge(START, "theorist")
workflow.add_edge("theorist", "precondition")

workflow.add_conditional_edges("precondition", route_precondition, {
    "poc_builder": "poc_builder",
    "triager1": "triager1",
    "loop_counter": "loop_counter",
})

workflow.add_conditional_edges("poc_builder", route_poc, {
    "impact_assessor": "impact_assessor",
    "poc_retry": "poc_retry",
    "triager1": "triager1",
})

# poc_retry → theorist'e geri döner (exploit_chain'i PoC hatasına göre düzeltsin)
workflow.add_edge("poc_retry", "theorist")

workflow.add_conditional_edges("triager1", route_triager1, {
    "triager2": "triager2",
    "loop_counter": "loop_counter",
    "end": END
})
workflow.add_conditional_edges("triager2", route_triager2, {
    "impact_assessor": "impact_assessor",
    "loop_counter": "loop_counter",
    "end": END
})
workflow.add_edge("impact_assessor", "final")
workflow.add_edge("final", END)
workflow.add_edge("loop_counter", "theorist")

app = workflow.compile()

# ==================== MAIN LOOP ====================
if __name__ == "__main__":
    logger.info("🚀 Solidity Guard 7/24 Otonom Tarama Modu Başlatılıyor (PoC-first mimari)...")
    logger.info(f" Groq key: {len(GROQ_KEYS)} | Cerebras key: {len(CEREBRAS_KEYS)}")

    forge_ready = poc_runner.check_forge_available()
    if forge_ready:
        logger.info(f"{GREEN}✅ Foundry mevcut - PoC-first mod aktif (mainnet fork doğrulaması){RESET}")
    else:
        logger.warning(f"{YELLOW}⚠️ Foundry mevcut değil - tüm bulgular metin-bazlı triager zincirinden geçecek{RESET}")

    repo_url = input("🔗 GitHub Repo URL girin (Enter = S3'teki mevcut contracts/ kullanılır): ").strip()
    local_path = "./target_repo"

    if not repo_url:
        logger.info("URL girilmedi. S3 contracts/ klasöründeki mevcut kontratlar kullanılıyor...")
        combined_code = load_contracts_from_s3()
        if not combined_code:
            logger.error("S3'te hiç kontrat bulunamadı! Önce bir repo yükleyin.")
            exit(1)
        scan_label = "S3:contracts/"
    else:
        combined_code, local_path = clone_and_upload_repo(repo_url)
        scan_label = repo_url

    logger.info(f"Kontrat kodu yüklendi. Toplam uzunluk: {len(combined_code)} karakter")
    logger.info(f"\n'{scan_label}' sonsuz döngüde taranıyor... (Ctrl+C ile durdur)\n")

    scan_count = 0
    while True:
        try:
            scan_count += 1
            run_id = f"{scan_count}_{int(time.time())}"
            logger.info(f"{CYAN}=== TARAMA #{scan_count} BAŞLIYOR (run_id={run_id}) ==={RESET}")
            app.invoke({
                "repo_url": scan_label,
                "repo_local_path": local_path,
                "contract_code": combined_code,
                "slither_report": "",
                "theorist_claim": "",
                "exploit_chain": "",
                "proofs": "",
                "precondition_result": {},
                "precondition_rendered": "",
                "poc_status": "",
                "poc_state_diff": "",
                "poc_error_summary": "",
                "poc_attempts": 0,
                "poc_retry_count": 0,
                "triager1_verdict": "",
                "triager2_verdict": "",
                "impact_assessment": "",
                "t2_dialogue": [],
                "last_rejection_context": "",
                "final_status": "",
                "loop_count": 0,
                "run_id": run_id,
            })
            logger.info(f"Tarama #{scan_count} tamamlandı. (Kaynak: {scan_label})")
            time.sleep(10)
        except KeyboardInterrupt:
            logger.info("👋 Sistem kullanıcı tarafından durduruldu.")
            break
        except Exception as e:
            err_msg = str(e)
            if "429" in err_msg and "tokens per day" in err_msg.lower():
                with _exhausted_lock:
                    for key in GROQ_KEYS:
                        if key not in _exhausted_groq_keys:
                            _exhausted_groq_keys.add(key)
                            logger.warning(f"⚠️ Groq key günlük limiti doldu → devre dışı bırakıldı. Kalan Groq key: {len(GROQ_KEYS) - len(_exhausted_groq_keys)}")
                            break
                time.sleep(5)
            else:
                logger.error(f"Döngü hatası (Tarama #{scan_count}): {err_msg}", exc_info=True)
                time.sleep(10)
