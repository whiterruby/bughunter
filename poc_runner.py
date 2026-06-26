"""
poc_runner.py
================================================================
PoC (Proof of Concept) çalıştırma motoru.

FELSEFE:
- Theorist'in ürettiği "exploit_chain" doğal dil anlatımıdır, kanıt değildir.
- Bu modül o anlatımı GERÇEK bir Foundry test dosyasına çevirip mainnet
  fork üzerinde ÇALIŞTIRIR.
- "Başarılı" sayılmanın tek kriteri revert almamak DEĞİLDİR. Attacker'ın
  net bir fayda elde ettiği STATE DIFF ile kanıtlanmalıdır (bakiye artışı,
  yetki ele geçirme, fiyat manipülasyonu vs. - PoC test dosyasının kendisi
  bunu assert eder).
- PoC çalışmazsa (forge yok / derleme hatası / fork hatası) bu ASLA
  "exploit yok" anlamına gelmez - belirsizdir. Böyle durumda pipeline
  eski metin-bazlı triager zincirine düşer (graceful degradation).
================================================================
"""

import os
import re
import shutil
import subprocess
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

FOUNDRY_BIN = os.path.expanduser(os.getenv("FOUNDRY_BIN", "~/.foundry/bin"))
ALCHEMY_URL = os.getenv("ALCHEMY_MAINNET_URL", "")  # .env: ALCHEMY_MAINNET_URL=https://eth-mainnet.g.alchemy.com/v2/<key>


@dataclass
class PoCResult:
    status: str  # "SUCCESS" | "FAIL" | "UNAVAILABLE" | "INCONCLUSIVE"
    raw_output: str = ""
    state_diff_proof: str = ""   # PoC içinde assert edilen, attacker faydasını gösteren log/diff
    attempted_code: str = ""     # Üretilen Solidity test dosyasının içeriği
    error_summary: str = ""      # Theorist'e geri verilecek, kısaltılmış hata özeti
    attempts_used: int = 0


def _resolve_forge_path() -> Optional[str]:
    """forge binary'sini PATH'te veya bilinen kurulum dizininde arar."""
    found = shutil.which("forge")
    if found:
        return found
    candidate = os.path.join(FOUNDRY_BIN, "forge")
    if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
        return candidate
    return None


def check_forge_available() -> bool:
    """
    Pipeline'ın PoC adımına girip girmeyeceğini belirleyen tek gerçek kaynak.
    main.py / graph routing bu fonksiyona bakar.
    """
    forge_path = _resolve_forge_path()
    if not forge_path:
        logger.warning("[PoC] forge bulunamadı → PoC adımı bu çalıştırma için devre dışı.")
        return False
    if not ALCHEMY_URL:
        logger.warning("[PoC] ALCHEMY_MAINNET_URL tanımlı değil → fork PoC çalıştırılamaz.")
        return False
    try:
        result = subprocess.run([forge_path, "--version"], capture_output=True, text=True, timeout=15)
        if result.returncode != 0:
            logger.warning(f"[PoC] forge --version başarısız: {result.stderr[:200]}")
            return False
        return True
    except Exception as e:
        logger.warning(f"[PoC] forge erişim kontrolü hatası: {e}")
        return False


def _ensure_foundry_scaffold(repo_local_path: str, work_dir: str) -> bool:
    """
    Repo karışık geliyor: bazen hazır foundry/hardhat projesi, bazen çıplak .sol.
    Bu fonksiyon work_dir içinde HER ZAMAN çalışır bir foundry iskeleti garanti eder.

    Strateji:
    1. work_dir'i temizle, foundry init et (forge-std dahil).
    2. repo_local_path'teki TÜM .sol dosyalarını work_dir/src/ altına kopyala
       (zaten foundry projesiyse src/ ve lib/ içeriğini de ayrıca kopyala).
    3. Hazır remappings.txt / foundry.toml varsa onları da taşı (import path'leri kırılmasın).
    """
    if os.path.exists(work_dir):
        shutil.rmtree(work_dir, ignore_errors=True)
    os.makedirs(work_dir, exist_ok=True)

    forge_path = _resolve_forge_path()
    if not forge_path:
        return False

    try:
        init_result = subprocess.run(
            [forge_path, "init", "--no-git", "--force"],
            cwd=work_dir, capture_output=True, text=True, timeout=60
        )
        if init_result.returncode != 0:
            logger.warning(f"[PoC] forge init hatası: {init_result.stderr[:300]}")
            # init başarısız olsa da devam etmeyi deneyebiliriz, src/ klasörünü manuel açalım
            os.makedirs(os.path.join(work_dir, "src"), exist_ok=True)
            os.makedirs(os.path.join(work_dir, "test"), exist_ok=True)
    except Exception as e:
        logger.warning(f"[PoC] forge init exception: {e}")
        os.makedirs(os.path.join(work_dir, "src"), exist_ok=True)
        os.makedirs(os.path.join(work_dir, "test"), exist_ok=True)

    # forge init varsayılan demo dosyalarını temizle
    for junk in ["src/Counter.sol", "test/Counter.t.sol", "script/Counter.s.sol"]:
        junk_path = os.path.join(work_dir, junk)
        if os.path.isfile(junk_path):
            os.remove(junk_path)

    dest_src = os.path.join(work_dir, "src")
    os.makedirs(dest_src, exist_ok=True)

    copied_any = False
    for root, _, files in os.walk(repo_local_path):
        # forge/hardhat'ın kendi lib/node_modules klasörlerini tekrar kopyalamayalım,
        # onları ayrıca ele alıyoruz aşağıda.
        if any(skip in root for skip in [f"{os.sep}lib{os.sep}", f"{os.sep}node_modules{os.sep}", f"{os.sep}.git{os.sep}"]):
            continue
        for file in files:
            if file.endswith(".sol"):
                src_path = os.path.join(root, file)
                rel = os.path.relpath(src_path, repo_local_path)
                dst_path = os.path.join(dest_src, rel)
                os.makedirs(os.path.dirname(dst_path), exist_ok=True)
                try:
                    shutil.copy2(src_path, dst_path)
                    copied_any = True
                except Exception as e:
                    logger.warning(f"[PoC] Dosya kopyalama hatası ({src_path}): {e}")

    # Repo zaten foundry projesiyse lib/ (forge-std vs bağımlılıklar) ve remappings'i de taşı
    existing_lib = os.path.join(repo_local_path, "lib")
    if os.path.isdir(existing_lib):
        dest_lib = os.path.join(work_dir, "lib")
        for item in os.listdir(existing_lib):
            src_item = os.path.join(existing_lib, item)
            dst_item = os.path.join(dest_lib, item)
            if not os.path.exists(dst_item):
                try:
                    if os.path.isdir(src_item):
                        shutil.copytree(src_item, dst_item)
                    else:
                        shutil.copy2(src_item, dst_item)
                except Exception:
                    pass

    for cfg_file in ["remappings.txt", "foundry.toml"]:
        src_cfg = os.path.join(repo_local_path, cfg_file)
        if os.path.isfile(src_cfg) and cfg_file != "foundry.toml":  # foundry.toml'u kendi forge init'imizin üzerine yazmayalım, RPC ayarları orada
            shutil.copy2(src_cfg, os.path.join(work_dir, cfg_file))

    return copied_any


def _write_foundry_toml(work_dir: str):
    """RPC endpoint ve fork ayarlarını foundry.toml içine yazar."""
    toml_path = os.path.join(work_dir, "foundry.toml")
    content = f"""[profile.default]
src = "src"
out = "out"
libs = ["lib"]
test = "test"
fs_permissions = [{{ access = "read", path = "./" }}]

[rpc_endpoints]
mainnet = "{ALCHEMY_URL}"
"""
    with open(toml_path, "w") as f:
        f.write(content)


def _extract_contract_names(contract_code: str) -> list:
    return re.findall(r'contract\s+(\w+)', contract_code)


def build_poc_test_file(
    work_dir: str,
    contract_code: str,
    theorist_claim: str,
    exploit_chain: str,
    proofs: str,
    preconditions: str,
    llm_invoke_fn,
) -> str:
    """
    LLM'i kullanarak exploit_chain'i ÇALIŞTIRILABİLİR bir Foundry test
    dosyasına çevirir. llm_invoke_fn: (prompt:str) -> str  şeklinde bir callback.

    KRİTİK KURAL (prompt içinde de vurgulanıyor): Test, attacker'a
    gerçekçi olmayan ön koşullar (sınırsız bakiye, sahte yetki, vm.prank
    ile owner taklit etmek gibi) vermemeli. Sadece gerçek bir attacker'ın
    mainnet'te sahip olabileceği koşullarla (kendi cüzdanı, public
    fonksiyon çağrıları, gerçek ETH/token miktarları) başlamalı.
    """
    contract_names = _extract_contract_names(contract_code)
    primary_contract = contract_names[0] if contract_names else "TargetContract"

    prompt = f"""Sen bir Foundry PoC mühendisisin. Görevin, aşağıdaki iddia edilen exploit'i
GERÇEKTEN ÇALIŞTIRILABİLİR bir Foundry test dosyasına çevirmek.

HEDEF KONTRAT(LAR): {', '.join(contract_names) if contract_names else '(isim bulunamadı, koda bak)'}

İDDİA: {theorist_claim}
EXPLOIT ZİNCİRİ: {exploit_chain}
ÖN KOŞULLAR (precondition extraction'dan): {preconditions}
KANITLAR: {proofs}

KOD (referans için, import path'i src/ klasörüne göre düşün):
{contract_code[:12000]}

KESİN KURALLAR:
1. Test mainnet fork üzerinde çalışmalı: `vm.createSelectFork(vm.rpcUrl("mainnet"))` kullan.
2. Attacker'a GERÇEKÇİ OLMAYAN avantaj VERME. Yasak: vm.prank ile owner/admin taklidi
   (kontrat owner kontrolü atlatılıyor diye iddia ediliyorsa bu zaten geçersiz bir PoC'tur),
   attacker'a deal/vm.deal ile gerçekçi olmayan miktarda token basmak, access control'ü
   doğrudan storage slot manipülasyonuyla bypass etmek.
3. İZİN VERİLEN: attacker'ın kendi adresine normal miktarda ETH vermek (gas için),
   public/external fonksiyonları çağırmak, gerçek mainnet kontratlarıyla (gerçek adresleriyle)
   etkileşime girmek.
4. Test İÇİNDE state-diff kanıtı zorunlu: exploit öncesi ve sonrası attacker'ın
   bakiyesini/yetkisini/hedef state'i ölç, `assertGt` veya `assertEq` ile FAYDA'yı kanıtla.
   Sadece "revert atmadı" yeterli değildir - testin kendisi net faydayı assert etmeli.
   Test başarısızsa (fayda kanıtlanamazsa) assert FAIL vermeli, böylece forge test bunu yakalar.
5. Test sonunda console.log ile "ATTACKER_BALANCE_BEFORE: X" ve "ATTACKER_BALANCE_AFTER: Y"
   (veya ilgili state için benzer format) yazdır - bunlar state-diff kanıtı olarak parse edilecek.
6. Dosya adı: Exploit.t.sol, kontrat adı: ExploitTest, pragma solidity ^0.8.0 veya kodun
   kendi pragma'sına uygun.
7. import "forge-std/Test.sol"; kullan. Hedef kontratı import etmen gerekiyorsa
   `import {{{primary_contract}}} from "../src/...";` formatını kullan, ama path'i bilmiyorsan
   ve tek dosyaysa gerekli kodu test dosyasının içine doğrudan kopyalayıp interface üzerinden
   mainnet'teki gerçek deployed adresle etkileşime gir (eğer adres biliniyorsa) - bilinmiyorsa
   yorum satırıyla "// KONTRAT ADRESİ BULUNAMADI, yerel deploy fallback" yaz ve `new {primary_contract}(...)` ile yerel deploy et.

SADECE SAF SOLIDITY KODU VER. Markdown fence, açıklama, JSON YOK. Direkt `// SPDX-License-Identifier` ile başla."""

    raw = llm_invoke_fn(prompt)
    # Markdown fence temizliği (model talimata uymazsa)
    clean = re.sub(r"^```solidity\s*|^```\s*|```$", "", raw.strip(), flags=re.MULTILINE).strip()
    return clean


def run_poc(
    repo_local_path: str,
    contract_code: str,
    theorist_claim: str,
    exploit_chain: str,
    proofs: str,
    preconditions: str,
    llm_invoke_fn,
    run_workspace: str = "./poc_workspace",
) -> PoCResult:
    """
    Ana giriş noktası. Çağıran taraf (graph node) bu fonksiyonu çağırır.
    Forge mevcut değilse ÇAĞRILMADAN ÖNCE check_forge_available() ile
    kontrol edilmeli - burada da bir kez daha güvenlik kontrolü yapılır.
    """
    if not check_forge_available():
        return PoCResult(status="UNAVAILABLE", error_summary="forge veya ALCHEMY_MAINNET_URL mevcut değil.")

    forge_path = _resolve_forge_path()

    logger.info("[PoC] Foundry scaffold hazırlanıyor...")
    scaffold_ok = _ensure_foundry_scaffold(repo_local_path, run_workspace)
    if not scaffold_ok:
        return PoCResult(status="INCONCLUSIVE", error_summary="Hedef .sol dosyaları work_dir'e kopyalanamadı.")

    _write_foundry_toml(run_workspace)

    logger.info("[PoC] LLM ile exploit test dosyası üretiliyor...")
    test_code = build_poc_test_file(
        run_workspace, contract_code, theorist_claim, exploit_chain, proofs, preconditions, llm_invoke_fn
    )

    test_dir = os.path.join(run_workspace, "test")
    os.makedirs(test_dir, exist_ok=True)
    test_path = os.path.join(test_dir, "Exploit.t.sol")
    with open(test_path, "w") as f:
        f.write(test_code)

    # forge-std bağımlılığı yoksa (init başarısız olduysa) install dene
    forge_std_path = os.path.join(run_workspace, "lib", "forge-std")
    if not os.path.isdir(forge_std_path):
        try:
            subprocess.run(
                [forge_path, "install", "foundry-rs/forge-std", "--no-git", "--no-commit"],
                cwd=run_workspace, capture_output=True, text=True, timeout=60
            )
        except Exception as e:
            logger.warning(f"[PoC] forge-std install hatası: {e}")

    logger.info("[PoC] forge test çalıştırılıyor (mainnet fork)...")
    try:
        result = subprocess.run(
            [forge_path, "test", "--match-path", "test/Exploit.t.sol", "-vvv"],
            cwd=run_workspace, capture_output=True, text=True, timeout=180
        )
    except subprocess.TimeoutExpired:
        return PoCResult(
            status="INCONCLUSIVE",
            attempted_code=test_code,
            error_summary="forge test 180 saniyede tamamlanmadı (timeout). Fork RPC yavaş olabilir."
        )
    except Exception as e:
        return PoCResult(
            status="INCONCLUSIVE",
            attempted_code=test_code,
            error_summary=f"forge test çalıştırma hatası: {e}"
        )

    output = (result.stdout or "") + "\n" + (result.stderr or "")

    if result.returncode == 0 and "[PASS]" in output:
        # State-diff kanıtını çıkarmaya çalış (console.log satırları)
        diff_lines = [l for l in output.splitlines() if "BALANCE_BEFORE" in l or "BALANCE_AFTER" in l or "ATTACKER_" in l]
        state_diff = "\n".join(diff_lines) if diff_lines else "(PoC PASS verdi ama açık state-diff log'u bulunamadı - manuel doğrulama önerilir)"
        return PoCResult(
            status="SUCCESS",
            raw_output=output[-4000:],
            state_diff_proof=state_diff,
            attempted_code=test_code,
        )

    # Derleme hatası mı, yoksa test fail mi ayır - bu theorist'e verilecek feedback'in kalitesini etkiler
    if "Compiler run failed" in output or "compilation error" in output.lower() or "error[" in output.lower():
        error_summary = "DERLEME HATASI:\n" + output[-1500:]
    elif "[FAIL" in output:
        error_summary = "TEST FAIL (assert/revert ile exploit kanıtlanamadı):\n" + output[-1500:]
    else:
        error_summary = "Bilinmeyen hata:\n" + output[-1500:]

    return PoCResult(
        status="FAIL",
        raw_output=output[-4000:],
        attempted_code=test_code,
        error_summary=error_summary,
    )
