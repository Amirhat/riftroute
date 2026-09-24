package server

// Landing-page copy, one struct per language. Everything user-facing lives
// here so the two languages stay in step.

type feature struct{ Glyph, Title, Body string }

// stop is a rule on the line diagram. Addr is an address, domain or
// interface (set in the mono face, always left-to-right).
type stop struct{ Addr, Name, Why string }

type step struct{ Name, Body string }

type privacyState struct{ Kind, Label, Text string }

type siteCopy struct {
	Lang, Dir, Other, OtherLabel string
	Title, Description           string
	Hero, Sub, Download, Source  string
	Platforms                    string

	// The line diagram: your computer, the fork, two lines.
	MapLabel, Origin                    string
	VPNLine, DirectLine                 string
	VPNStops, DirectStops               []stop
	VPNEnd, DirectEnd                   string
	LegendVPN, LegendDirect, LegendStop string
	MapNote                             string

	SafetyTitle, SafetyLead string
	Steps                   []step // preview, apply, confirm
	Kept, RolledBack, Panic step

	FeaturesTitle string
	Features      []feature
	ShotAlt       string
	ShotCaption   string

	PrivacyTitle string
	Privacy      []privacyState

	CloseTitle string
	License    string
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
	Download:  "Download",
	Source:    "Source on GitHub",
	Platforms: "macOS (Apple Silicon & Intel) · Linux · free and open source (MIT)",

	MapLabel:   "Example: traffic from your computer splits between the VPN and a direct connection",
	Origin:     "Your computer",
	VPNLine:    "Through the VPN",
	DirectLine: "Direct",
	VPNStops:   []stop{{Name: "Everything else", Why: "default route"}},
	DirectStops: []stop{
		{Addr: "10.0.0.0/8", Why: "Work profile"},
		{Addr: "*.example.com", Why: "domain rule · 3 addresses learned"},
		{Addr: "192.168.1.0/24", Why: "Home list"},
	},
	VPNEnd:       "the internet, through the tunnel",
	DirectEnd:    "the internet, on your own connection",
	LegendVPN:    "through the VPN",
	LegendDirect: "direct",
	LegendStop:   "a rule",
	MapNote:      "Example rules. Ask RiftRoute about any address and it tells you which line it takes — and why.",

	SafetyTitle: "Safe by design",
	SafetyLead:  "A mistake ends in “no change” or “undone” — never in “no network”. Every change runs this line:",
	Steps: []step{
		{"Preview", "See every route that will change, before anything does."},
		{"Apply", "It all lands as one transaction, with its undo worked out in advance."},
		{"Confirm", "Keep the change — or do nothing."},
	},
	Kept:       step{"Kept", "Your rules stay in place."},
	RolledBack: step{"Rolled back", "No confirmation, or the connection dropped: it undoes itself."},
	Panic:      step{"Panic", "One button puts everything back at once."},

	FeaturesTitle: "What it does",
	Features: []feature{
		{"fork", "Exclude or include", "Send everything through the VPN except what you choose — or only what you choose. Works alongside the VPN you already use."},
		{"domain", "Domains and wildcards", "Route \u2066example.com\u2069 and \u2066*.example.com\u2069; RiftRoute learns the addresses behind them as your apps use them."},
		{"buffer", "A kill switch that won't cut your VPN", "Keeps your apps inside the tunnel if the VPN drops — and steps aside rather than cut a VPN's own connection."},
		{"watch", "See what's happening", "Live routing table, per-connection flows, leak and DNS checks, and a history of every change."},
		{"report", "Private bug reports", "Reports are built on your computer with addresses, domains and names replaced. You decide what to share."},
	},
	ShotAlt:     "RiftRoute answering “Where does traffic go?” for 10.20.30.40: direct, through 10.0.0.0/8 on en0, because of the work-bypass profile",
	ShotCaption: "The real app, on its built-in simulator: ask where an address goes and it shows the route — and the rule behind it.",

	PrivacyTitle: "Your privacy",
	Privacy: []privacyState{
		{"today", "Today", "RiftRoute runs on your computer. It has no account and sends nothing today; it only contacts GitHub when you press “Check for updates”."},
		{"later", "Later", "Future versions may send anonymous usage counts to improve it. You'll be told first, see exactly what would be sent, and can turn it off in one click."},
		{"never", "Never", "Never sent, at any setting: IP addresses, domains, profile, app or user names, network names, or your computer's name."},
	},

	CloseTitle: "Download RiftRoute",
	License:    "MIT License",
}

var copyFA = siteCopy{
	Lang: "fa", Dir: "rtl", Other: "/", OtherLabel: "English",
	Title:       "RiftRoute — تقسیم ترافیکی که می‌شود به آن اعتماد کرد",
	Description: "تعیین کنید چه ترافیکی از VPN برود و چه ترافیکی مستقیم — بر اساس آدرس، دامنه یا برنامه — بدون این‌که هرگز از شبکه بیرون بمانید.",
	Hero:        "تقسیم ترافیکی که می‌شود به آن اعتماد کرد.",
	Sub: "تعیین کنید چه ترافیکی از VPN برود و چه ترافیکی مستقیم — بر اساس محدودهٔ آدرس، دامنه (همراه زیردامنه‌ها) یا برنامه. " +
		"RiftRoute هر تغییر را به‌صورت یک تراکنش برگشت‌پذیر اعمال می‌کند؛ یک قانون اشتباه شما را از شبکه بیرون نمی‌اندازد.",
	Download:  "دانلود",
	Source:    "کد منبع در GitHub",
	Platforms: "مک (اپل سیلیکون و اینتل) · لینوکس · رایگان و متن‌باز (MIT)",

	MapLabel:   "نمونه: ترافیک کامپیوتر شما بین VPN و اتصال مستقیم تقسیم می‌شود",
	Origin:     "کامپیوتر شما",
	VPNLine:    "از داخل VPN",
	DirectLine: "مستقیم",
	VPNStops:   []stop{{Name: "بقیهٔ ترافیک", Why: "مسیر پیش‌فرض"}},
	DirectStops: []stop{
		{Addr: "10.0.0.0/8", Why: "پروفایل «کار»"},
		{Addr: "*.example.com", Why: "قانون دامنه · ۳ آدرس یاد گرفته شد"},
		{Addr: "192.168.1.0/24", Why: "فهرست «خانه»"},
	},
	VPNEnd:       "اینترنت، از داخل تونل",
	DirectEnd:    "اینترنت، از اتصال خودتان",
	LegendVPN:    "از داخل VPN",
	LegendDirect: "مستقیم",
	LegendStop:   "یک قانون",
	MapNote:      "قانون‌های نمونه. دربارهٔ هر آدرسی از RiftRoute بپرسید؛ می‌گوید از کدام خط می‌رود — و چرا.",

	SafetyTitle: "ایمن از پایه",
	SafetyLead:  "هر اشتباه یا به «هیچ تغییری نکرد» می‌رسد یا به «خودش برگشت» — هرگز به «اینترنت قطع شد». هر تغییر از این خط می‌گذرد:",
	Steps: []step{
		{"پیش‌نمایش", "پیش از هر تغییری، همهٔ مسیرهایی را که عوض می‌شوند می‌بینید."},
		{"اعمال", "همه‌اش یکجا و به‌صورت یک تراکنش اعمال می‌شود و راه برگشتش از قبل آماده است."},
		{"تأیید", "تغییر را نگه دارید — یا هیچ کاری نکنید."},
	},
	Kept:       step{"ماند", "قانون‌هایتان سر جایشان می‌مانند."},
	RolledBack: step{"خودش برگشت", "تأیید نکردید یا اتصال قطع شد: تغییر خودش برمی‌گردد."},
	Panic:      step{"Panic", "یک دکمه همه‌چیز را فوراً به حالت اول برمی‌گرداند."},

	FeaturesTitle: "چه کار می‌کند",
	Features: []feature{
		{"fork", "استثنا یا انحصار", "همه‌چیز از VPN برود جز آنچه انتخاب می‌کنید — یا فقط آنچه انتخاب می‌کنید. در کنار همان VPNی که دارید کار می‌کند."},
		{"domain", "دامنه‌ها و زیردامنه‌ها", "\u2066example.com\u2069 و \u2066*.example.com\u2069 را مسیردهی کنید؛ RiftRoute آدرس‌های پشت آن‌ها را هنگام استفادهٔ برنامه‌ها یاد می‌گیرد."},
		{"buffer", "کیل‌سوییچی که VPN را قطع نمی‌کند", "اگر VPN قطع شود، برنامه‌هایتان را داخل تونل نگه می‌دارد — و به‌جای قطع کردن اتصال خودِ VPN، کنار می‌کشد."},
		{"watch", "ببینید چه می‌گذرد", "جدول مسیرها، اتصال‌های زنده، بررسی نشت و DNS، و تاریخچهٔ همهٔ تغییرات."},
		{"report", "گزارش خطای خصوصی", "گزارش روی کامپیوتر خودتان ساخته می‌شود و آدرس‌ها، دامنه‌ها و نام‌ها در آن جایگزین می‌شوند. شما تصمیم می‌گیرید چه چیزی را به اشتراک بگذارید."},
	},
	ShotAlt:     "RiftRoute به پرسش «ترافیک کجا می‌رود؟» برای \u206610.20.30.40\u2069 پاسخ می‌دهد: مستقیم، از مسیر \u206610.0.0.0/8\u2069 روی \u2066en0\u2069، به‌خاطر پروفایل \u2066work-bypass\u2069",
	ShotCaption: "خودِ برنامه، روی شبیه‌ساز داخلی‌اش: بپرسید یک آدرس کجا می‌رود؛ مسیر را نشان می‌دهد — و قانونی را که پشتش است.",

	PrivacyTitle: "حریم خصوصی شما",
	Privacy: []privacyState{
		{"today", "امروز", "RiftRoute روی کامپیوتر خودتان اجرا می‌شود؛ حساب کاربری ندارد و امروز هیچ داده‌ای نمی‌فرستد. فقط وقتی دکمهٔ \u2066Check for updates\u2069 را بزنید به GitHub وصل می‌شود."},
		{"later", "بعدها", "نسخه‌های بعدی ممکن است آمار ناشناس استفاده بفرستند تا محصول بهتر شود. قبلش به شما گفته می‌شود، دقیقاً می‌بینید چه چیزی فرستاده می‌شود و با یک کلیک خاموشش می‌کنید."},
		{"never", "هرگز", "در هیچ تنظیمی فرستاده نمی‌شود: آدرس IP، دامنه، نام پروفایل، برنامه یا کاربر، نام شبکه یا نام کامپیوتر شما."},
	},

	CloseTitle: "RiftRoute را دانلود کنید",
	License:    "مجوز MIT",
}
