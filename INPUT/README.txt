Is folder me apni log files daalo - naam kuch bhi ho sakta hai.

Chalega:
  - Windows: .evtx file (Event Viewer -> Security -> Save All Events As) ya XML export
  - Linux:   auth.log / secure (koi bhi naam, .gz bhi chalega)
  - AWS:     CloudTrail ka JSON download (koi bhi naam)
  - Upar wali files ki .zip

Phir run.bat -> option 1 (Web Console) -> "Analyse INPUT folder"
ya run.bat -> option 6 (Analyse INPUT folder).

Framework khud har file ke andar dekh ke pehchaanta hai ki wo Windows, Linux ya AWS ki hai.
Original files kabhi badli nahi jaati - unki copy par kaam hota hai aur SHA-256 hash note hota hai.
