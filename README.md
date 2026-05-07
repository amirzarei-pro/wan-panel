# WAN Live Panel

پنل مانیتورینگ **read-only** برای چند WAN روی لینوکس.

## امکانات
- نمایش سرعت هر WAN (Upload/Download) با استفاده از **nftables counter objects**
- وضعیت Gateway/Internet + کیفیت لینک: **RTT / Loss / Jitter** (بدون پکیج اضافه)
- نمایش وضعیت لینک (Interface up/down) و شمارنده‌های سادهٔ **drop/error** برای هر WAN
- مانیتور منابع سیستم: CPU / RAM / Swap / Disk / Load / Uptime
- UI تک صفحه‌ای با دو تب: `WAN / Panel` و `System Resources`
- بدون CDN و بدون کتابخانهٔ JS خارجی

> نمودارها بعد از Refresh هم با استفاده از `/api/history` پر می‌شوند.

> این پروژه عمداً هیچ اکشن تغییر‌دهنده‌ای مثل Set Default Route ندارد.

## پیش‌نیازها
- Linux + Python **3.10+**
- ابزارها: `ip` (iproute2), `ping` (iputils-ping), `nft` (nftables)
- دسترسی لازم برای اجرای `nft`/`ip`/`ping` (روی خیلی از سرورها سرویس را به صورت root اجرا می‌کنند)

## نصب سریع
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp config.example.json config.json
# config.json را مطابق سرور خودتان ویرایش کنید

python3 app.py
```
سپس در مرورگر:
- `http://SERVER_IP:5088/`

## تنظیمات (config.json)
مسیر config به صورت پیش‌فرض کنار `app.py` است و با env زیر هم قابل تغییر است:
- `WAN_PANEL_CONFIG=/path/to/config.json`

کلیدهای مهم:
- `bind_host`, `port`
- `wans`: آبجکت شامل WANها (کلید = `wan_id`)
- `internet_test_ips`: لیست IP برای تست اینترنت (اولین مقصدی که پاسخ بده استفاده می‌شود)
- `nft_table_family`, `nft_table_name`: جدول nft که counterها در آن هستند

## nftables counters
اپ برای محاسبهٔ سرعت، بایت‌های counterها را از nft می‌خواند:
```bash
nft -j list counters table inet wanmon
```
نمونهٔ اسکلت در فایل زیر هست (قواعد را باید مطابق شبکه خودتان تکمیل کنید):
- `nftables/wanmon.example.nft`

## systemd (نمونه)
فایل نمونه:
- `systemd/wan-panel.service.example`

روال کلی نصب:
```bash
sudo cp systemd/wan-panel.service.example /etc/systemd/system/wan-panel.service
sudo systemctl daemon-reload
sudo systemctl enable --now wan-panel.service
```

## نکتهٔ امنیتی
اگر این پنل را روی اینترنت پابلیک می‌کنید، پیشنهاد می‌شود پشت Reverse Proxy + Auth اجرا شود و مستقیم روی `0.0.0.0` بدون محدودیت شبکه منتشر نشود.
