#!/usr/bin/env bash
# ============================================================
# Foundry Kurulum Script'i
# ============================================================
# Bu script container başlangıcında çalışır. Amaç: forge/cast/anvil
# komutlarını kullanılabilir hale getirmek.
#
# ÖNEMLİ: Bu script BAŞARISIZ OLURSA pipeline durmaz.
# main.py içindeki check_forge_available() fonksiyonu forge'un
# çalışıp çalışmadığını runtime'da kontrol eder ve yoksa PoC adımını
# atlayıp eski metin-bazlı triager zincirine düşer (graceful degradation).
#
# Bu yüzden burada `set -e` KULLANMIYORUZ - her adım kendi hata
# kontrolünü yapıyor ve script hiçbir zaman non-zero exit ile
# pipeline'ı kilitlemiyor.
# ============================================================

FOUNDRY_DIR="${FOUNDRY_DIR:-$HOME/.foundry}"
FOUNDRY_BIN="$FOUNDRY_DIR/bin"

echo "[setup_foundry] Foundry kurulum kontrolü başlıyor..."

# Zaten kuruluysa hiçbir şey yapma
if command -v forge >/dev/null 2>&1; then
    echo "[setup_foundry] ✅ forge zaten PATH'te bulundu: $(command -v forge)"
    forge --version || true
    exit 0
fi

if [ -x "$FOUNDRY_BIN/forge" ]; then
    echo "[setup_foundry] ✅ forge $FOUNDRY_BIN içinde bulundu, PATH'e ekleniyor"
    export PATH="$FOUNDRY_BIN:$PATH"
    echo "export PATH=\"$FOUNDRY_BIN:\$PATH\"" >> "$HOME/.bashrc" 2>/dev/null || true
    exit 0
fi

echo "[setup_foundry] forge bulunamadı, kuruluyor (foundryup ile)..."

# curl yoksa kurulum yapılamaz, sessizce çık (main.py fallback'i devreye alacak)
if ! command -v curl >/dev/null 2>&1; then
    echo "[setup_foundry] ⚠️ curl bulunamadı, Foundry kurulamıyor. PoC adımı devre dışı kalacak."
    exit 0
fi

# Resmi foundryup installer - network yoksa bu satır timeout/hata verir,
# ama script devam eder (set -e yok)
INSTALL_OUTPUT=$(curl -L --max-time 30 https://foundry.paradigm.xyz 2>&1 | bash 2>&1)
INSTALL_STATUS=$?

if [ $INSTALL_STATUS -ne 0 ]; then
    echo "[setup_foundry] ⚠️ foundryup installer indirilemedi (network kısıtı olabilir)."
    echo "[setup_foundry] PoC adımı devre dışı kalacak, pipeline metin-bazlı triager'a düşecek."
    exit 0
fi

# foundryup komutu artık PATH'te olmalı (genelde ~/.foundry/bin altına kurulur)
export PATH="$FOUNDRY_BIN:$PATH"

if command -v foundryup >/dev/null 2>&1; then
    echo "[setup_foundry] foundryup bulundu, forge/cast/anvil indiriliyor..."
    foundryup --no-modify-path >/tmp/foundryup.log 2>&1
    FOUNDRYUP_STATUS=$?
    if [ $FOUNDRYUP_STATUS -ne 0 ]; then
        echo "[setup_foundry] ⚠️ foundryup başarısız oldu. Log: /tmp/foundryup.log"
        echo "[setup_foundry] PoC adımı devre dışı kalacak."
        exit 0
    fi
else
    echo "[setup_foundry] ⚠️ foundryup PATH'te bulunamadı. Kurulum eksik kalmış olabilir."
    exit 0
fi

# Son doğrulama
if [ -x "$FOUNDRY_BIN/forge" ]; then
    echo "[setup_foundry] ✅ Foundry kurulumu tamamlandı."
    "$FOUNDRY_BIN/forge" --version || true
    echo "export PATH=\"$FOUNDRY_BIN:\$PATH\"" >> "$HOME/.bashrc" 2>/dev/null || true
else
    echo "[setup_foundry] ⚠️ Kurulum tamamlandı ama forge binary'si bulunamadı. PoC adımı devre dışı kalacak."
fi

exit 0
