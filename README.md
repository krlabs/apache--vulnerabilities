# Список вразливостей веб-сервера Apache

Публікується з метою контролю безпеки сайтів на базі веб-серверів Apache. На замітку дослідникам та власникам електронних ресурсів. В рамках волонтерського проєкту "За вільний і безпечний UAnet!".

Дані вразливості були виявлені дослідниками KR. Laboratories в ході глобального аудиту ресурсів українського сегменту мережі Інтернет й можуть бути використані як легітимними пентестерами, так і зловмисниками для проведення таких атак як: переповнення буфера (buffer overflow), Denial of Service / Distributed Denial of Service Attack (DoS/DDoS), Path Traversal, Local File Inclusion / Remote File Inclusion (LFI/RFI), Cross Site Scripting Attack (XSS), Cross Site Request Forgery / Server Side Request Forgery (CSRF/SSRF), розкриття конфіденційної інформації (Expose Sensitive Information / Information Disclosure), пошкодження або втрата даних, помилки конфігураці та багато інших.   

Ми рекомендуємо українським веб-майстрам і системним адміністраторам регулярно оновлювати серверне програмне забезпечення та використовувати наші рекомендації щодо кібербезпеки, аби мінімізувати потенційні ризики.  

З приводу захисту веб-серверів пишіть нам на електронну скриньку: security[@]kr-labs.com.ua

| **CVE Ідентифікатор** &nbsp; &nbsp; | **Опис** | **Exploit / PoC** |
|-----------------------------------------------------|----------|-------------|
| [**CVE-2007-5000**](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5000)| Вразливість у модулі mod_imagemap дозволяє провести XSS-атаку. | [Експлойт](http://example.com/exploit/6420) |
| [**CVE-2007-6420**](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6420) | Вразливість у модулі mod_proxy_balancer дозволяє провести CSRF-атаку. | N/a |
| [**CVE-2007-6421**](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6421) | Вразливість у модулі mod_proxy_balancer дозволяє провести XSS-атаку. |
| [**CVE-2007-6422**](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6422) | Вразливість у модулі mod_proxy_balancer дозволяє викликати відмову в обслуговуванні. |
| [**CVE-2007-6399**](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6399) | Вразливість у модулі mod_status дозволяє провести XSS-атаку. |
| [**CVE-2008-0005**](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0005) | Вразливість у модулі mod_proxy_ftp дозволяє провести XSS-атаку на сервери з включеним модулем. |
| [**CVE-2008-0456**](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0456) | Вразливість CRLF у модулі mod_negotiation дозволяє провести response splitting атаку. |
| [**CVE-2008-2364**](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2364) | Вразливість у модулі mod_proxy_http дозволяє віддаленому атакуючому викликати відмову в обслуговуванні (DoS). |
| [**CVE-2008-2939**](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2939) | Вразливість дозволяє впровадити сценарій і провести XSS-атаку через FTP-шлях. |
| [**CVE-2009-1890**](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1890) | Вразливість у модулі mod_proxy дозволяє викликати відмову в обслуговуванні. |
| [**CVE-2009-1891**](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1891) | Вразливість у модулі mod_deflate дозволяє викликати відмову в обслуговуванні. |
| [**CVE-2009-3094**](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3094) | Вразливість у модулі mod_proxy_ftp може призводити до відмови в обслуговуванні. |
| [**CVE-2009-3095**](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3095) | Вразливість у модулі mod_proxy_ftp дозволяє віддаленому атакуючому посилати довільні команди FTP-серверу. |
| [**CVE-2009-3560**](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3560) | Дозволяє атакуючому, залежному від контексту, викликати відмову в обслуговуванні («падіння» застосунку) за допомогою спеціально створеного XML-документа з неправильною UTF-8 послідовністю, яка викликає переповнення буфера. Вразливість пов'язана з функцією doProlog у бібліотеці /xmlparse.c. |
| [**CVE-2009-3720**](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3720) | Дозволяє атакуючому, залежному від контексту, викликати відмову в обслуговуванні («падіння» застосунку) за допомогою спеціально створеного XML-документа з неправильною UTF-8 послідовністю, яка викликає переповнення буфера. |
| [**CVE-2010-0408**](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-0408) | Вразливість у модулі mod_proxy_ajp дозволяє викликати відмову в обслуговуванні. |
| [**CVE-2010-1452**](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-1452) | Вразливість у модулях mod_cache та mod_dav дозволяє викликати відмову в обслуговуванні. |
| [**CVE-2010-1623**](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-1623) | Дозволяє зловмиснику (віддалено) викликати відмову в обслуговуванні (надмірне споживання пам’яті). |
| [**CVE-2011-0419**](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-0419) | Дозволяє викликати відмову в обслуговуванні (DoS) через використання спеціально сформованих регулярних виразів у запитах, що спричиняють високі витрати CPU і пам’яті. Ця проблема впливає на модуль `mod_autoindex`. | [Експлойт](https://www.exploit-db.com/exploits/35738) |
| [**CVE-2011-3192**](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192) | Дозволяє зловмиснику (віддалено) викликати відмову в обслуговуванні (пам’ять і процесор) через заголовок Range, який виражає кілька перекриваючихся діапазонів. | [Експлойт 1](https://github.com/limkokholefork/CVE-2011-3192) [Експлойт 2](https://www.exploit-db.com/exploits/17696)
| [**CVE-2011-3348**](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3348) | Дозволяє зловмиснику (віддалено) викликати відмову в обслуговуванні (тимчасовий «стан помилки» на внутрішньому сервері) через неправильно сформований HTTP-запит. |
| [**CVE-2011-3368**](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3368) | Дозволяє зловмиснику (віддалено) відправити запит на сервери внутрішньої мережі. | [Експлойт](https://www.exploit-db.com/exploits/17969) |
| [**CVE-2011-3607**](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3607) | Дозволяє локальному користувачу підвищити свої права в системі. | [Експлойт](https://www.exploit-db.com/exploits/41769) |
| [**CVE-2011-3639**](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3639) | Вразливість дозволяє викликати відмову в обслуговуванні через використання HTTP/0.9. |
| [**CVE-2011-4317**](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-4317) | Вразливість у модулі proxy дозволяє обходити обмеження доступу. | [Експлойт](https://www.exploit-db.com/exploits/36352) |
| [**CVE-2011-4415**](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-4415) | Локальний користувач може викликати відмову в обслуговуванні. |
| [**CVE-2012-0031**](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-0031) | Дозволяє локальному користувачу викликати «відмову в обслуговуванні». |
| [**CVE-2012-0053**](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-0053) | Дозволяє зловмиснику отримати HTTPOnly cookies за допомогою спеціально сформованого веб-скрипта. | [Експлойт](https://github.com/jonathansp/CVE20120053Demo) |
| [**CVE-2012-0031**](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-0031) | Локальний користувач може викликати відмову в обслуговуванні. |
| [**CVE-2012-2687**](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-2687) | Вразливість у модулі mod_negotiation дозволяє провести XSS-атаку. |
| [**CVE-2012-0883**](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-0883) | Локальний користувач може підвищити привілеї. |
| [**CVE-2016-8740**](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-8740) | Вразливість у модулі HTTP/2 в Apache HTTP Server дозволяє викликати відмову в обслуговуванні (DoS) через некоректну обробку певних HTTP/2 запитів. Вразливість пов'язана з тим, як сервер обробляє спеціально сформовані запити у HTTP/2. | [Експлойт](https://www.exploit-db.com/exploits/40909) |
| [**CVE-2019-0211**](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-0211) | Дозволяє локальному користувачу, який має доступ до HTTP-сервера, підвищувати свої привілеї до прав суперкористувача (root). Це можливо через некоректну обробку певних запитів у MPM (Multi-Processing Module) | [Експлойт 1](https://github.com/cfreal/exploits/blob/master/CVE-2019-0211-apache/README.md) | [Експлойт 2](https://www.exploit-db.com/exploits/46676)
| [**CVE-2021-41773**](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41773)  | Дозволяє зловмисникам здійснювати атаки типу Path Traversal, що може призвести до несанкціонованого доступу до файлів за межами кореневого каталогу документа. | [PoC 1](https://github.com/lorddemon/CVE-2021-41773-PoC) [PoC 2](https://github.com/iilegacyyii/PoC-CVE-2021-41773) | [Експлойт](https://github.com/battleoverflow/apache-traversal) |
| [**CVE-2021-42013**](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42013) | Дозволяє зловмисникам здійснювати атаки типу Path Traversal і навіть виконувати довільний код на сервері. Це стає можливим через неправильне виправлення попередньої вразливості CVE-2021-41773. | [Експлойт](https://github.com/battleoverflow/apache-traversal) |
| [**CVE-2023-43622**](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-43622) | Вразливість у Apache HTTP Server версій від 2.4.55 до 2.4.57 дозволяє зловмиснику встановити HTTP/2-з'єднання з початковим розміром вікна 0, що призводить до блокування обробки цього з'єднання на невизначений час. Це може вичерпати ресурси сервера, подібно до атаки "slowloris". | [Експлойт](https://github.com/visudade/CVE-2023-43622/blob/main/exploit.py)
| [**CVE-2023-38709**](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-38709) | Неправильна перевірка вхідних даних у ядрі Apache дозволяє зловмисникам маніпулювати відповідями HTTP | [Експлойт](https://github.com/mrmtwoj/apache-vulnerability-testing/blob/main/poc_vulnerability_testing.py)
| [**CVE-2024-27316**](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-27316) | Вхідні заголовки HTTP/2, що перевищують ліміт, тимчасово буферизуються в nghttp2, щоб сформувати код відповіді HTTP 413. Якщо зловмисник не припиняє надсилати заголовки, це призводить до виснаження пам’яті і падіння сервера. | [Експлойт](https://github.com/lockness-Ko/CVE-2024-27316) |
| [**CVE-2024-38472**](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38472) | SSRF вразливість у HTTP-сервері Apache під Windows дозволяє потенційно витікати хеші NTLM на зловмисний сервер через SSRF і зловмисні запити або вміст. | [PoC](https://github.com/mrmtwoj/apache-vulnerability-testing/blob/main/poc_vulnerability_testing.py) |
| [**CVE-2024-38473**](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38473) | Вразливість у Apache HTTP Server, яка дозволяє обійти обмеження доступу до захищених ресурсів через спеціально сформовані запити. | [PoC](https://github.com/mrmtwoj/apache-vulnerability-testing/blob/main/poc_vulnerability_testing.py) [Експлойт](https://sploitus.com/exploit?id=249A954E-0189-5182-AE95-31C866A057E1)|
| [**CVE-2024-38474**](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38474) | Вразливість у модулі mod_headers, яка дозволяє викликати відмову в обслуговуванні через некоректну обробку певних заголовків HTTP. |
| [**CVE-2024-38475**](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38475) | Вразливість у модулі mod_rewrite, яка дозволяє обходити налаштування безпеки через некоректно оброблені правила перепису. | [PoC 1](https://github.com/mrmtwoj/apache-vulnerability-testing/blob/main/poc_vulnerability_testing.py) [PoC 2](https://github.com/p0in7s/CVE-2024-38475) |
| [**CVE-2024-38476**](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38476) | Вразливість у HTTP/2 обробнику, що дозволяє викликати відмову в обслуговуванні через спеціально сформовані запити. | [PoC](https://github.com/mrmtwoj/apache-vulnerability-testing/blob/main/poc_vulnerability_testing.py) |
| [**CVE-2024-38477**](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-38477) | Вразливість у модулі mod_ssl, яка може призвести до витоку даних через некоректну обробку TLS-з’єднань. | [PoC](https://github.com/mrmtwoj/apache-vulnerability-testing/blob/main/poc_vulnerability_testing.py) |
| [**CVE-2024-39573**](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-39573) | Вразливість у модулі mod_proxy, що дозволяє зловмисникам отримати доступ до внутрішніх ресурсів сервера через помилки у конфігурації проксі. | [PoC](https://github.com/mrmtwoj/apache-vulnerability-testing/blob/main/poc_vulnerability_testing.py) |

### Джерела
- [TrustWave. Hunting For Integer Overflows In Web Servers](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/hunting-for-integer-overflows-in-web-servers/)
- [PICUS. Five Ways to Simulate Apache CVE-2021-41773 Exploits](https://www.picussecurity.com/resource/blog/simulate-apache-cve-2021-41773-exploits-vulnerability)
- [Qualys Community. Apache HTTP Server Path Traversal & Remote Code Execution (CVE-2021-41773 & CVE-2021-42013)](https://blog.qualys.com/vulnerabilities-threat-research/2021/10/27/apache-http-server-path-traversal-remote-code-execution-cve-2021-41773-cve-2021-42013)
- [Medium. CVE-2024–40725 and CVE-2024–40898: Critical Vulnerabilities in Apache HTTP Server](https://infosecwriteups.com/cve-2024-40725-and-cve-2024-40898-critical-vulnerabilities-in-apache-http-server-d292084255dc)
- [Orange Tsai. Confusion Attacks: Exploiting Hidden Semantic Ambiguity in Apache HTTP Server!](https://blog.orange.tw/posts/2024-08-confusion-attacks-en/)
- [Medium.Exploit Apache HTTP Server Vulnerabilities](https://medium.com/@sebastienwebdev/exploit-apache-http-server-vulnerabilities-a18049ee1f05)
- [ExploitDB. Apache Vulnerabilities](https://www.exploit-db.com/?search=apache)
- [ZeroDay.cz. 0-Zero-Day Vulnerabilities](https://www.zero-day.cz)
- [Apache HTTP Server Vulnerability Testing Tool](https://github.com/mrmtwoj/apache-vulnerability-testing)
- [ReconScan](https://github.com/RoliSoft/ReconScan)
- [NMAP Vuln NSE](https://nmap.org/nsedoc/categories/vuln.html)
- [NMAP Script Vulners](https://nmap.org/nsedoc/scripts/vulners.html)
- [KR.Laboratories. Google Dorks Gold Collection](https://kr-labs.com.ua/blog/google-dorks-for-osint/)
- [KR. Laboratories. Cyber Threat Intelligence Platforms and Search Engines list](https://kr-labs.com.ua/blog/search-engines-for-penetration-tester/)
- [Feedly. Threat Intelligence. CVE Trending](https://feedly.com/cve)
- [Apache HTTP Server 2.4 vulnerabilities](https://httpd.apache.org/security/vulnerabilities_24.html)
- [Cyber Secutity News. Critical Apache HTTP Server Vulnerabilities Expose Millions of Websites to Cyber Attack](https://cybersecuritynews.com/critical-apache-http-server-vulnerabilities/)
