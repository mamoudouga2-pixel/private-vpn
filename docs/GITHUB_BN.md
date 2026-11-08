# গিটহাবে তোলা (ফোন থেকে, Termux দিয়ে)

ব্রাউজারে "Upload files" দিয়ে ফোল্ডারসহ সব ফাইল তোলা যায় না, ফোনে ফোল্ডার বাছা যায় না। তাই Termux দিয়ে তুলুন।

## ধাপ ১: গিটহাবে খালি রিপো বানান
১. github.com-এ ঢুকুন, New repository চাপুন।
২. নাম দিন `private-vpn`। **Private** বেছে নিন।
৩. "Add a README" বা অন্য কিছু টিক দেবেন না। Create চাপুন।

## ধাপ ২: টোকেন বানান (পাসওয়ার্ডের বদলে)
Settings → Developer settings → Personal access tokens → Tokens (classic) → Generate new token (classic)।
- নাম: `private-vpn`
- টিক দিন: **repo** আর **workflow**
- Generate চাপুন, টোকেনটা কপি করে নোটে রাখুন। এটা আর দেখাবে না। কাউকে দেবেন না।

## ধাপ ৩: Termux-এ কমান্ড
```
pkg install -y git unzip
termux-setup-storage
cd ~
unzip ~/storage/downloads/PRIVATE_VPN.zip
cd NovaVPN_Private_Network_MVP
git config --global user.name "আপনার নাম"
git config --global user.email "আপনার@ইমেইল.com"
git init
git add .
git commit -m "first upload"
git branch -M main
git remote add origin https://github.com/আপনার-ইউজারনেম/private-vpn.git
git push -u origin main
```
(ইউজারনেম আর ইমেইল ইংরেজিতে দিন।) পুশের সময় ইউজারনেম চাইলে গিটহাব ইউজারনেম দিন। পাসওয়ার্ডের জায়গায় **টোকেন** পেস্ট করুন। লিখলে স্ক্রিনে কিছু দেখাবে না, এটা স্বাভাবিক।

## ধাপ ৪: APK পাওয়া (নিজে নিজেই বানাবে)
জিপের ভেতরে APK ফাইল থাকে না। গিটহাব সার্ভারে সেটা বানায়। আপনাকে কিছু বানাতে হবে না।

১. কোড পুশ করার পর রিপোতে **Actions** ট্যাব খুলুন। "Build PRIVATE VPN Android APK" নামে একটা কাজ চলতে দেখবেন (হলুদ ঘুরছে)।
২. ৫-১০ মিনিট পরে সবুজ টিক এলে হয়ে গেছে।
৩. রিপোর প্রথম পাতায় ডানে **Releases** লেখা অংশে "PRIVATE VPN - latest build" চাপুন।
৪. নিচে **PRIVATE-VPN.apk** চাপলে ফোনে নামবে। নামিয়ে খুলে ইনস্টল করুন (অজানা উৎস থেকে ইনস্টলের অনুমতি চাইলে দিন)।

**Actions-এ কিছু না চললে:** Actions ট্যাবে বাঁ পাশে "Build PRIVATE VPN Android APK" চাপুন → ডানে "Run workflow" → সবুজ বোতাম।
**Actions ট্যাবে কিছুই না থাকলে:** `.github` ফোল্ডারটা আপলোড হয়নি। টোকেনে **workflow** টিক ছিল কি না দেখুন।
**লাল ক্রস এলে:** ওই রানে ঢুকে লাল অংশের স্ক্রিনশট আমাকে দিন।

প্রতিবার কোড বদলে পুশ করলে নতুন APK নিজে নিজেই তৈরি হয়ে ওই একই Releases পাতায় আসবে।
