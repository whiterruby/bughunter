"""
precondition.py
================================================================
FELSEFE (sohbette konuşulan kök sorun):
Eski sistemde triager'lara "bu exploit mantıklı mı?" diye soruluyordu.
LLM'ler tutarlı görünen hikayeleri onaylamaya çok meyilli, çünkü onay
vermek için sadece verilen mantığı takip etmesi yeterli - karşı kanıt
üretmesi gerekmiyor.

Bu modül onun yerine exploit_chain'i ATOMİK ÖN KOŞULLARA ayırır:
"attacker bu state'e nasıl ulaşır, hangi msg.sender/value/önceki
transaction gerekir" - ve HER BİR önkoşulu ayrı ayrı, kodun kendisine
bakarak doğrulat/çürütmeye çalışır. Genel "mantıklı mı" sorusu yerine
"bu önkoşul kodda gerçekten mümkün mü" sorusu sorulur.

Bu adım PoC üretiminden ÖNCE çalışır - hem PoC'un hangi senaryoyu test
edeceğini netleştirir, hem de PoC üretilemediğinde (forge yok) metin-bazlı
triager'a daha güçlü bir girdi sağlar.
================================================================
"""

import re
import json
import logging

logger = logging.getLogger(__name__)


def _safe_json_list(text: str) -> list:
    try:
        clean = re.sub(r"```json\s*|```", "", text.strip())
        start = clean.find("[")
        end = clean.rfind("]") + 1
        if start != -1 and end > start:
            return json.loads(clean[start:end])
        return json.loads(clean)
    except Exception:
        return []


def extract_preconditions(
    contract_code: str,
    theorist_claim: str,
    exploit_chain: str,
    llm_invoke_fn,
) -> dict:
    """
    Exploit chain'i atomik önkoşullara ayırır ve her birini kod üzerinde
    bağımsız olarak değerlendirir.

    Dönüş formatı:
    {
        "preconditions": [
            {
                "step": "Attacker X fonksiyonunu Y parametresiyle çağırır",
                "requires": "Hiçbir özel yetki gerekmiyor, public fonksiyon",
                "verifiable_in_code": true/false,
                "verdict": "PLAUSIBLE" | "IMPLAUSIBLE" | "UNCERTAIN",
                "reasoning": "..."
            },
            ...
        ],
        "weakest_link": "En zayıf/şüpheli önkoşulun özeti",
        "overall_plausible": true/false
    }
    """
    prompt = f"""Sen bir akıllı kontrat güvenlik analistisin. Görevin "bu exploit mantıklı mı"
diye GENEL bir soru sormak DEĞİL - exploit zincirini ATOMİK ÖN KOŞULLARA ayırıp
HER BİRİNİ kodun kendisine bakarak tek tek, bağımsız olarak sorgulamak.

İDDİA: {theorist_claim}
EXPLOIT ZİNCİRİ: {exploit_chain}

KOD:
{contract_code[:14000]}

Her adım için kendine şunu sor: "Attacker bu spesifik state'e/yetkiye/koşula
GERÇEKTEN ulaşabilir mi, yoksa bu teorist'in VARSAYIMI mı?" Özellikle şunlara dikkat et:
- Owner/admin yetkisi gerektiren bir adım var mı? Varsa attacker bunu nasıl elde ediyor?
- Reentrancy iddiası varsa, checks-effects-interactions sırası GERÇEKTEN ihlal ediliyor mu,
  yoksa state zaten external call'dan ÖNCE güncelleniyor mu?
- Belirli bir initial state/bakiye/onay (approval) gerekiyor mu? Bu gerçekçi mi?
- Birden fazla transaction/blok gerekiyor mu? Aradaki sürede başka bir aktör müdahale edebilir mi?

ÇIKTI - SADECE SAF JSON ARRAY (markdown, açıklama yok):
[
  {{
    "step": "Adımın kısa açıklaması",
    "requires": "Bu adımın gerçekleşmesi için attacker'ın sahip olması gereken şey",
    "verifiable_in_code": true,
    "verdict": "PLAUSIBLE",
    "reasoning": "Kodun hangi satırı/mantığı bunu destekliyor veya çürütüyor"
  }}
]

verdict alanı SADECE şu üçünden biri olabilir: "PLAUSIBLE", "IMPLAUSIBLE", "UNCERTAIN"."""

    raw = llm_invoke_fn(prompt)
    steps = _safe_json_list(raw)

    if not steps:
        logger.warning("[Precondition] JSON parse edilemedi, ham metin fallback kullanılıyor.")
        return {
            "preconditions": [],
            "weakest_link": "(Ayrıştırma başarısız - ham model çıktısı triager'a aktarılacak)",
            "overall_plausible": None,
            "raw_fallback": raw,
        }

    implausible_steps = [s for s in steps if s.get("verdict") == "IMPLAUSIBLE"]
    uncertain_steps = [s for s in steps if s.get("verdict") == "UNCERTAIN"]

    if implausible_steps:
        overall_plausible = False
        weakest_link = implausible_steps[0].get("reasoning", implausible_steps[0].get("step", ""))
    elif uncertain_steps:
        overall_plausible = None  # belirsiz, PoC'a veya triager'a havale
        weakest_link = uncertain_steps[0].get("reasoning", uncertain_steps[0].get("step", ""))
    else:
        overall_plausible = True
        weakest_link = "(Tüm adımlar PLAUSIBLE olarak değerlendirildi)"

    return {
        "preconditions": steps,
        "weakest_link": weakest_link,
        "overall_plausible": overall_plausible,
    }


def render_preconditions_for_prompt(precondition_result: dict) -> str:
    """Triager / PoC builder prompt'larına gömülecek okunabilir özet."""
    steps = precondition_result.get("preconditions", [])
    if not steps:
        return precondition_result.get("raw_fallback", "(Önkoşul verisi yok)")

    lines = []
    for i, s in enumerate(steps, 1):
        lines.append(
            f"{i}. [{s.get('verdict', '?')}] {s.get('step', '')}\n"
            f"   Gereken: {s.get('requires', '')}\n"
            f"   Gerekçe: {s.get('reasoning', '')}"
        )
    lines.append(f"\nEN ZAYIF HALKA: {precondition_result.get('weakest_link', '')}")
    return "\n".join(lines)
