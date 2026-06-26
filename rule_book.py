"""
rule_book.py
================================================================
Self-learning'in "ham log biriktirme" yerine "distile edilmiş kural
biriktirme" hali.

FELSEFE:
Eski sistemde self-learning context'i ham rejection metinlerini olduğu
gibi tekrar theorist'e veriyordu. Sorun: theorist aynı YANLIŞ ZAFİYET
SINIFINI (örn. "sahte reentrancy varsayımı") farklı kelimelerle tekrar
üretiyordu, çünkü ham metin pattern'i öğretmiyor, sadece "bu spesifik
cümleyi tekrar etme" diyordu.

Bu modül her rejection'dan SONRA bir LLM çağrısı ile o reddi 1 cümlelik
genel bir kurala indirir (örn. "Bu kontratta X fonksiyonu zaten Y kontrolü
yaptığı için reentrancy iddiaları geçersizdir") ve bunu rule_book.json
içinde S3'te biriktirir. theorist her çalıştığında bu kural kitabının
TAMAMINI (özet halde) görür - ham rejection loglarını değil.

Kural kitabı kontrat/repo bazlı tutulur (repo_fingerprint ile), çünkü
bir repodan çıkan kural başka bir repoya rastgele uygulanmamalı.
"""

import os
import json
import hashlib
import logging
import boto3

logger = logging.getLogger(__name__)

S3_BUCKET = os.getenv("S3_BUCKET", "solidity-guard-vault")
s3 = boto3.client("s3")

MAX_RULES_KEPT = 40  # kural kitabı şişmesin, en güncel N kural tutulur


def repo_fingerprint(repo_label: str) -> str:
    return hashlib.sha256(repo_label.encode("utf-8")).hexdigest()[:16]


def _rule_book_key(repo_label: str) -> str:
    return f"self-learning/rule_books/{repo_fingerprint(repo_label)}.json"


def load_rule_book(repo_label: str) -> list:
    key = _rule_book_key(repo_label)
    try:
        body = s3.get_object(Bucket=S3_BUCKET, Key=key)["Body"].read().decode("utf-8", "ignore")
        data = json.loads(body)
        return data.get("rules", [])
    except Exception:
        return []


def save_rule_book(repo_label: str, rules: list):
    key = _rule_book_key(repo_label)
    try:
        s3.put_object(
            Bucket=S3_BUCKET,
            Key=key,
            Body=json.dumps({"rules": rules[-MAX_RULES_KEPT:]}, ensure_ascii=False, indent=2).encode("utf-8"),
        )
    except Exception as e:
        logger.warning(f"[RuleBook] S3 kayıt hatası: {e}")


def distill_rejection_to_rule(
    theorist_claim: str,
    exploit_chain: str,
    rejection_reason: str,
    llm_invoke_fn,
) -> str:
    """
    Bir reddi genel, tekrar kullanılabilir bir kurala indirir.
    llm_invoke_fn: (prompt:str) -> str
    """
    prompt = f"""Aşağıda bir akıllı kontrat zafiyet iddiası ve bu iddianın neden reddedildiği var.
Bunu, GELECEKTE AYNI SINIFTAKİ HATALI İDDİALARI ENGELLEYECEK genel, tekrar kullanılabilir
TEK BİR CÜMLELİK kural haline getir. Spesifik fonksiyon adlarından ziyade, hatanın
GENEL MANTIK SINIFINA odaklan (örn. "X fonksiyonu" değil, "harici çağrı öncesi state
güncellenen pattern'ler reentrancy iddiası için yeterli değildir, checks-effects-interactions
sıralaması da kontrol edilmeli").

İDDİA: {theorist_claim}
EXPLOIT ZİNCİRİ: {exploit_chain}
RED GEREKÇESİ: {rejection_reason}

SADECE TEK CÜMLE ver, başka hiçbir şey yazma. Markdown, başlık, açıklama YOK."""

    try:
        rule = llm_invoke_fn(prompt).strip()
        # Çok uzun gelirse (model talimatı dinlemediyse) ilk cümleye indir
        if len(rule) > 400:
            rule = rule.split(".")[0].strip() + "."
        return rule
    except Exception as e:
        logger.warning(f"[RuleBook] Distillation hatası: {e}")
        return f"(Distillation başarısız - ham gerekçe) {rejection_reason[:200]}"


def add_rejection_and_distill(
    repo_label: str,
    theorist_claim: str,
    exploit_chain: str,
    rejection_reason: str,
    llm_invoke_fn,
) -> str:
    """
    Tek çağrıda: kuralı distile et, kural kitabına ekle, S3'e kaydet.
    Dönüş: eklenen kural metni (loglama için).
    """
    rule = distill_rejection_to_rule(theorist_claim, exploit_chain, rejection_reason, llm_invoke_fn)
    rules = load_rule_book(repo_label)

    # Basit dedup: aynı kural zaten varsa tekrar ekleme
    if rule not in rules:
        rules.append(rule)
        save_rule_book(repo_label, rules)
        logger.info(f"[RuleBook] Yeni kural eklendi: {rule[:120]}")
    else:
        logger.info("[RuleBook] Kural zaten mevcut, tekrar eklenmedi.")

    return rule


def render_rule_book_for_prompt(repo_label: str) -> str:
    """theorist prompt'una eklenecek, okunabilir kural listesi."""
    rules = load_rule_book(repo_label)
    if not rules:
        return "(Bu repo için henüz birikmiş kural yok.)"
    numbered = "\n".join(f"{i+1}. {r}" for i, r in enumerate(rules))
    return f"=== BU REPO İÇİN BİRİKMİŞ KURALLAR (geçmiş reddedilen iddialardan distile edildi) ===\n{numbered}"
