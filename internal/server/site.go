package server

// Landing-page copy, one struct per language. Everything user-facing lives
// here so the two languages stay in step.

type feature struct{ Title, Body string }

type siteCopy struct {
	Lang, Dir, Other, OtherLabel string
	Title, Description           string
	Hero, Sub, Download, Source  string
	Platforms                    string
	ShotAlt                      string
	FeaturesTitle                string
	Features                     []feature
	PrivacyTitle                 string
	Privacy                      []string
	License                      string
}

const (
	releasesURL = "https://github.com/Amirhat/riftroute/releases/latest"
	sourceURL   = "https://github.com/Amirhat/riftroute"
)

var copyEN = siteCopy{
	Lang: "en", Dir: "ltr", Other: "/fa", OtherLabel: "فارسی",
	Title:       "RiftRoute — split tunneling you can trust",
	Description: "Decide what goes through your VPN and what goes direct — by address, domain or app — without ever locking yourself off the network.",
	Hero:        "Split tunneling you can trust.",
	Sub: "Decide what goes through your VPN and what goes direct — by address range, domain (subdomains included) or app. " +
		"RiftRoute applies every change as a reversible transaction, so a bad rule can't lock you off the network.",
	Download:      "Download",
	Source:        "Source on GitHub",
	Platforms:     "macOS (Apple Silicon & Intel) · Linux · free and open source (MIT)",
	ShotAlt:       "The RiftRoute dashboard: VPN status, default route, managed routes and interfaces",
	FeaturesTitle: "What it does",
	Features: []feature{
		{"Exclude or include", "Send everything through the VPN except what you choose — or only what you choose. Works alongside the VPN you already use."},
		{"Domains and wildcards", "Route example.com and *.example.com; RiftRoute learns the addresses behind them as your apps use them."},
		{"Safe by design", "Every change is previewed, applied as one transaction, and rolled back on its own if you lose connectivity or don't confirm. Panic restores everything at once."},
		{"A kill switch that won't cut your VPN", "Keeps your apps inside the tunnel if the VPN drops — and steps aside rather than cut a VPN's own connection."},
		{"See what's happening", "Live routing table, per-connection flows, leak and DNS checks, and a history of every change."},
		{"Private bug reports", "Reports are built on your computer with addresses, domains and names replaced. You decide what to share."},
	},
	PrivacyTitle: "Your privacy",
	Privacy: []string{
		"RiftRoute runs on your computer. It has no account and sends nothing today.",
		"Future versions may send anonymous usage counts to improve it. You'll be told first, see exactly what would be sent, and can turn it off in one click.",
		"Never sent, at any setting: IP addresses, domains, profile, app or user names, network names, or your computer's name.",
	},
	License: "MIT License",
}

var copyFA = siteCopy{
	Lang: "fa", Dir: "rtl", Other: "/", OtherLabel: "English",
	Title:       "RiftRoute — تقسیم ترافیکی که می‌شود به آن اعتماد کرد",
	Description: "تعیین کنید چه ترافیکی از VPN برود و چه ترافیکی مستقیم — بر اساس آدرس، دامنه یا برنامه — بدون این‌که هرگز از شبکه بیرون بمانید.",
	Hero:        "تقسیم ترافیکی که می‌شود به آن اعتماد کرد.",
	Sub: "تعیین کنید چه ترافیکی از VPN برود و چه ترافیکی مستقیم — بر اساس محدودهٔ آدرس، دامنه (همراه زیردامنه‌ها) یا برنامه. " +
		"RiftRoute هر تغییر را به‌صورت یک تراکنش برگشت‌پذیر اعمال می‌کند؛ یک قانون اشتباه شما را از شبکه بیرون نمی‌اندازد.",
	Download:      "دانلود",
	Source:        "کد منبع در GitHub",
	Platforms:     "مک (اپل سیلیکون و اینتل) · لینوکس · رایگان و متن‌باز (MIT)",
	ShotAlt:       "داشبورد RiftRoute: وضعیت VPN، مسیر پیش‌فرض، مسیرهای مدیریت‌شده و رابط‌های شبکه",
	FeaturesTitle: "چه کار می‌کند",
	Features: []feature{
		{"استثنا یا انحصار", "همه‌چیز از VPN برود جز آنچه انتخاب می‌کنید — یا فقط آنچه انتخاب می‌کنید. در کنار همان VPNی که دارید کار می‌کند."},
		{"دامنه‌ها و زیردامنه‌ها", "\u2066example.com\u2069 و \u2066*.example.com\u2069 را مسیردهی کنید؛ RiftRoute آدرس‌های پشت آن‌ها را هنگام استفادهٔ برنامه‌ها یاد می‌گیرد."},
		{"ایمن از پایه", "هر تغییر پیش‌نمایش می‌شود، یکجا اعمال می‌شود و اگر اتصال قطع شود یا تأیید نکنید، خودکار برمی‌گردد. دکمهٔ Panic همه‌چیز را فوراً به حالت اول برمی‌گرداند."},
		{"کیل‌سوییچی که VPN را قطع نمی‌کند", "اگر VPN قطع شود، برنامه‌هایتان را داخل تونل نگه می‌دارد — و به‌جای قطع کردن اتصال خودِ VPN، کنار می‌کشد."},
		{"ببینید چه می‌گذرد", "جدول مسیرها، اتصال‌های زنده، بررسی نشت و DNS، و تاریخچهٔ همهٔ تغییرات."},
		{"گزارش خطای خصوصی", "گزارش روی کامپیوتر خودتان ساخته می‌شود و آدرس‌ها، دامنه‌ها و نام‌ها در آن جایگزین می‌شوند. شما تصمیم می‌گیرید چه چیزی را به اشتراک بگذارید."},
	},
	PrivacyTitle: "حریم خصوصی شما",
	Privacy: []string{
		"RiftRoute روی کامپیوتر خودتان اجرا می‌شود؛ حساب کاربری ندارد و امروز هیچ داده‌ای نمی‌فرستد.",
		"نسخه‌های بعدی ممکن است آمار ناشناس استفاده بفرستند تا محصول بهتر شود. قبلش به شما گفته می‌شود، دقیقاً می‌بینید چه چیزی فرستاده می‌شود و با یک کلیک خاموشش می‌کنید.",
		"در هیچ تنظیمی فرستاده نمی‌شود: آدرس IP، دامنه، نام پروفایل، برنامه یا کاربر، نام شبکه یا نام کامپیوتر شما.",
	},
	License: "مجوز MIT",
}
