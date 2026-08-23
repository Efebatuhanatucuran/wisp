<p align="center">
  <img src="assets/wisp.svg" width="90" alt="Wisp maskotu">
</p>

<h1 align="center">Wisp</h1>

<p align="center"><em>English: <a href="README.md">README.md</a></em></p>

[Model Context Protocol](https://modelcontextprotocol.io) (MCP) sunucu konfigürasyonları için
statik bir güvenlik tarayıcısı — Claude Desktop, Cursor, VS Code ve diğer AI istemcilerine hangi
araçları çağırabileceğini söyleyen config dosyalarını tarar.

Agentic AI kullanımı yaygınlaştıkça, hatalı yapılandırılmış veya kötü niyetli MCP sunucuları
gerçek bir saldırı yüzeyi haline geliyor: bir config, bir agent'a doğrudan bir shell verebilir,
sürümü sabitlenmemiş (ve altında sessizce değişebilecek) bir paket çalıştırabilir, düz metin
halinde bir API anahtarı barındırabilir ya da hiç denetlemediğin bir uzak endpoint'e bağlanabilir.
Wisp bu tür sorunları, sunucuyu hiç çalıştırmadan, *çalıştırmadan önce* buluyor.

## Neleri kontrol ediyor

| Kural | Kontrol ettiği |
|------|------------|
| R001 | Sunucu, kapsamlı bir binary yerine doğrudan bir shell (`bash`, `sh`, `powershell`, ...) çalıştırıyor |
| R002 | MCP sunucu paketi `npx`/`uvx` vb. ile, sürümü sabitlenmeden çalıştırılıyor (tedarik zinciri riski) |
| R003 | Config içinde düz metin olarak duran API anahtarı / token / parola |
| R004 | Uzak (localhost olmayan) endpoint'ler, özellikle şifrelenmemiş HTTP |
| R005 | İzin atlatan flag'ler veya tüm dosya sistemine erişim (`/`, `~`, `--dangerously-skip-permissions`) |
| R006 | Privileged Docker container'ları veya bağlanmış Docker socket'i |
| R007 | Bozuk/belirsiz sunucu tanımları |
| R008 | Config'in kendi içine gömülmüş prompt-injection tarzı metin |
| R009 | Sürüm/digest'e sabitlenmemiş Docker image'ları (floating `:latest`) |
| R010 | Sunucu paketinin bilinen, yayınlanmış bir güvenlik açığı var (CVE/GHSA, osv.dev üzerinden) — opsiyonel, aşağıya bak |
| R011 | (INFO) Bir credential, environment-variable passthrough ile doğru şekilde dışarıda tutulmuş |

Her bulgunun bir önem derecesi (INFO → CRITICAL) var ve tüm tarama tek bir 0–100 risk skoruna
dönüşüyor.

## Kurulum

```bash
pip install -e .
```

Web arayüzü için de:

```bash
pip install -e ".[web]"
```

(PyPI paketi ileride gelecek — şimdilik kaynak koddan klonlayıp kur.)

## Kullanım

```bash
# Bilinen istemci config'lerini (Claude Desktop, Cursor, VS Code, Windsurf)
# ve mevcut projedeki .mcp.json'ı otomatik bulup hepsini tara:
wisp scan

# Belirli bir dosyayı tara:
wisp scan --config path/to/mcp.json

# JSON/HTML rapor yaz (HTML paylaşılabilir tek sayfalık bir rapor):
wisp scan --json report.json --html report.html

# Sunucu paketlerini osv.dev üzerinden bilinen CVE'lerle de karşılaştır
# (ağa çıkan tek flag; varsayılan olarak kapalı):
wisp scan --check-cve

# CI modu — HIGH veya üzeri bir bulgu varsa sıfır olmayan bir kodla çık:
wisp scan --fail-on HIGH
```

## Örnek

```bash
wisp scan --config examples/risky-config.json
```

Bilerek riskli yazılmış örnek bir config ve ürettiği rapor için [`examples/`](examples/) klasörüne
bak.

## Web arayüzü

```bash
wisp serve
```

Terminal yerine etkileşimli tarama yapabileceğin lokal bir panel açar (varsayılan
`http://127.0.0.1:8765`): otomatik bulunan config'lerden seç, bir dosyayı sürükle-bırak, ya da
hazır riskli/temiz örnekleri yükle; bulgular sunucuya göre gruplanır, severity'e göre filtrelenir,
raporlar JSON/HTML olarak indirilebilir. Yukarıdaki minik parlayan maskot Wisp — başlığın yanında
duruyor ve taramadan sonra risk skoruna göre renk değiştiriyor. Web arayüzünün CLI'de olmayan iki
özelliği:

- **CVE eşleştirmesi** (varsayılan açık, kapatılabilir): her sunucu paketini
  [osv.dev](https://osv.dev) ile karşılaştırıp bilinen güvenlik açıklarını R010 bulgusu olarak
  işaretler.
- **MCP CVE akışı**: "Model Context Protocol" geçen güncel CVE'leri izleyen bir panel ([NVD](https://nvd.nist.gov)
  anahtar kelime aramasıyla), `serve` çalıştığı sürece arka planda 6 saatte bir otomatik
  yenilenir, ayrıca elle yenileme butonu da var.

## Neden varsayılan olarak sadece config (canlı bağlantı yok)?

Çekirdek tarayıcı bilinçli olarak statik: MCP istemcinin sunucuya vereceği JSON'ı, hiç ağ çağrısı
yapmadan ve hiç kod çalıştırmadan ayrıştırıyor. Bu da henüz tam güvenmediğin config'leri güvenle
taramanı sağlıyor ve neyi gerçekten kontrol ettiğini net tutuyor. `--check-cve` (CLI) ve web
arayüzü bunun bilinçli tek istisnası — osv.dev/NVD'ye sorup *bilinen*, zaten yayınlanmış güvenlik
açıklarını kontrol ediyorlar, makinen hakkında bir şey incelemiyorlar. Canlı inceleme (çalışan bir
sunucunun araç listesini çekip *araç açıklamalarını* prompt-injection payload'ları için taramak,
[AgentDojo](https://github.com/ethz-spylab/agentdojo)'nun test ettiğine benzer şekilde) doğal
sonraki adım — [Roadmap](#roadmap)'e bak.

## Roadmap

- [ ] Canlı mod: stdio/SSE sunuculara bağlanıp gerçek araç açıklamalarını/şemalarını tara
- [ ] Allowlist/baseline dosyası, CI sadece *yeni* bulgularda başarısız olsun diye
- [ ] `pip`/`brew` dağıtımı
- [ ] Docker image'larının kendisi için güvenlik açığı taraması (sadece npm/PyPI paketleri değil)

## Lisans

MIT — bkz. [LICENSE](LICENSE).
