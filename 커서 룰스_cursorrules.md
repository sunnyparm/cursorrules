목차
//PRP 프레임워크 생성 방법
// Awesome CursorRules
//스니펫] 팝업으로 파일 선택
//스니펫] 텔레그램봇
//스니펫] DB 구조 + 데이터 확인
//스케쥴러사용
//pythoanywhere 파이썬애니웨어 #가상환경
//크롤링_정보입력방식_"fiil()" vs "type()"
//커서에서_가상환경만들기
//프롬프트_웹페이지크롤링

//프롬프트_웹페이지크롤링

아래코드를 참고해서 해당 ｕｒｌ 데이터를 수집한다. 
url: https://www.autismkorea.kr/bbs/board.php?tbl=bbs31 #공지사항

출력예시는 다음과 같다.
1. 제목: [공지] 2025년 제6회 그림공모전 결과 발표
   링크: https://www.autismkorea.kr/bbs/board.php?tbl=bbs31&mode=VIEW&num=1064
   일자: 2025-09-11
'''
    코드
    import requests
    from bs4 import BeautifulSoup
    from datetime import datetime, timedelta
    from urllib.parse import urljoin, urlparse, parse_qs
    import re
    import sqlite3
    import urllib3
    import ssl
    from urllib3.poolmanager import PoolManager
    from requests.adapters import HTTPAdapter
    try:
        import chardet  # optional
    except Exception:
        chardet = None

    DB_PATH = 'disablednews_sent.db'
    TEST_MODE = True  # 테스트용: DB/텔레그램 비활성화, 크롤링 결과만 출력
    DEBUG_LIST_ALL = True  # 디버그: 날짜 필터와 무관하게 모든 행의 제목/일자를 출력
    DAYS_WINDOW = 5  # 최근 N일 이내만 수집
    HEADER_TITLE = '한국자폐인사랑협회 기사'

    def init_db():
        if TEST_MODE:
            return
        with sqlite3.connect(DB_PATH) as conn:
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS sent_news (
                    title TEXT,
                    date TEXT,
                    PRIMARY KEY (title, date)
                )
            """)
            conn.commit()

    def is_already_sent(title, date):
        if TEST_MODE:
            return False
        with sqlite3.connect(DB_PATH) as conn:
            cur = conn.cursor()
            cur.execute("SELECT 1 FROM sent_news WHERE title = ? AND date = ?", (title, date))
            return cur.fetchone() is not None

    def save_sent(title, date):
        if TEST_MODE:
            return
        with sqlite3.connect(DB_PATH) as conn:
            cur = conn.cursor()
            try:
                cur.execute("INSERT INTO sent_news (title, date) VALUES (?, ?)", (title, date))
                conn.commit()
            except sqlite3.IntegrityError:
                pass

    # ==============================
    # 수집 대상 URL
    # ==============================
    urls = [
        'https://www.autismkorea.kr/bbs/board.php?tbl=bbs31',  # 공지사항
        'https://www.autismkorea.kr/bbs/board.php?tbl=bbs36',  # 뉴스레터
        'https://www.autismkorea.kr/bbs/board.php?tbl=bbs32',  # 언론보도
        'https://www.autismkorea.kr/bbs/board.php?tbl=bbs34'   # 외부기관 소식
    ]

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
    }

    # SSL 검증 경고 비활성화 (verify=False 사용 시)
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    class TLSAdapter(HTTPAdapter):
        def init_poolmanager(self, *args, **kwargs):
            ctx = ssl.create_default_context()
            # 일부 서버의 약한 DH 파라미터 문제(DH_KEY_TOO_SMALL) 우회를 위해 보안 레벨을 낮춘다
            try:
                ctx.set_ciphers('DEFAULT@SECLEVEL=1')
            except ssl.SSLError:
                pass
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            self.poolmanager = PoolManager(*args, ssl_context=ctx, **kwargs)

    session = requests.Session()
    session.mount('https://', TLSAdapter())

    five_days_ago = datetime.now() - timedelta(days=DAYS_WINDOW)
    msg = ''
    count = 1
    debug_count = 1  # DEBUG_LIST_ALL 출력용 순번

    init_db()

    for url in urls:
        print(f"요청 시작: {url}")
        try:
            res = session.get(url, headers=headers, timeout=15, verify=False)
            print(f"상태 코드: {res.status_code}, 응답 길이: {len(res.content)}")
        except Exception as e:
            print(f"요청 실패: {e}")
            continue
        # 응답 인코딩 판별: meta > headers > chardet > cp949 백업
        raw = res.content
        enc_candidates = []
        # meta charset 추출
        try:
            head_snippet = raw[:4096].decode('ascii', errors='ignore')
            m = re.search(r'charset=([\w\-]+)', head_snippet, re.IGNORECASE)
            if m:
                enc_candidates.append(m.group(1).lower())
        except Exception:
            pass
        if res.encoding:
            enc_candidates.append(res.encoding.lower())
        if chardet is not None:
            try:
                detected = chardet.detect(raw).get('encoding')
                if detected:
                    enc_candidates.append(detected.lower())
            except Exception:
                pass
        # 한국 사이트 일반 백업 인코딩
        enc_candidates += ['utf-8', 'cp949', 'euc-kr']
        # 후보 중 한글 검출되는 첫 디코딩 사용
        selected = None
        for enc in enc_candidates:
            try:
                trial = raw.decode(enc, errors='replace')
                if re.search(r'[\uac00-\ud7a3]', trial):
                    selected = enc
                    html = trial
                    break
            except Exception:
                continue
        if selected is None:
            # 마지막 백업
            html = raw.decode('utf-8', errors='replace')
        soup = BeautifulSoup(html, 'html.parser')

        # -----------------------------
        # (1) 한국자폐인사랑협회 공지사항
        # -----------------------------
        table = soup.find('table', class_='basic_board_list')
        if not table:
            # Fallback: 카드형 목록 (ul.horizontal_board > li)
            items = soup.select('ul.horizontal_board li')
            if not items:
                print("목록 테이블/카드 목록을 찾지 못했습니다.")
                continue
            print(f"카드형 목록 개수: {len(items)}")
            for li in items:
                a_tag = li.select_one('div.txt_box h4 a') or li.select_one('h4 a')
                if not a_tag:
                    continue
                title = a_tag.get_text(strip=True)
                link = a_tag.get('href')
                full_url = urljoin(url, link)
                # VIEW 링크 정규화
                try:
                    parsed = urlparse(full_url)
                    qs = parse_qs(parsed.query)
                    num = qs.get('num', [None])[0]
                    tbl = qs.get('tbl', [''])[0]
                    if num:
                        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                        if not tbl:
                            # 원본 URL의 tbl 유지 시도
                            orig_qs = parse_qs(urlparse(url).query)
                            tbl = orig_qs.get('tbl', [''])[0]
                        if tbl:
                            full_url = f"{base}?tbl={tbl}&mode=VIEW&num={num}"
                except Exception:
                    pass

                # 날짜 추출: '작성일' 주변 또는 YYYY-MM-DD 패턴 찾기
                date_key = None
                date_obj = None
                em = li.select_one('em')
                date_text = em.get_text(" ", strip=True) if em else li.get_text(" ", strip=True)
                m = re.search(r'(20\d{2}-\d{2}-\d{2})', date_text)
                if m:
                    date_key = m.group(1)
                    try:
                        y, mo, d = map(int, date_key.split('-'))
                        date_obj = datetime(y, mo, d)
                    except Exception:
                        date_obj = None

                if not date_key or not date_obj:
                    # 다른 포맷 시도: YY.MM.DD
                    m2 = re.search(r'(\d{2})\.(\d{2})\.(\d{2})', date_text)
                    if m2:
                        y = int('20' + m2.group(1))
                        mo = int(m2.group(2))
                        d = int(m2.group(3))
                        try:
                            date_obj = datetime(y, mo, d)
                            date_key = date_obj.strftime('%Y-%m-%d')
                        except Exception:
                            date_key = None

                if not date_key:
                    # 날짜 없으면 스킵
                    continue

                if DEBUG_LIST_ALL:
                    print(f"{debug_count}\t{title}\t{date_key}\t{full_url}")
                    debug_count += 1

                if date_obj >= five_days_ago:
                    if not is_already_sent(title, date_key):
                        line = f"{count}\t{title}\t{date_key}\t{full_url}"
                        print(line)
                        msg += line + "\n"
                        save_sent(title, date_key)
                        count += 1
            # 카드형을 처리했으므로 테이블 파싱은 건너뜀
            continue
        rows = table.find_all('tr')

        print(f"행 개수: {len(rows)}")
        for row in rows:
            td_left = row.find('td', class_='left')
            if not td_left:
                continue

            a_tag = td_left.find('a')
            if not a_tag:
                continue

            title = a_tag.text.strip()
            link = a_tag.get('href')
            full_url = urljoin(url, link)
            # 깔끔한 VIEW 링크로 정규화: ...&mode=VIEW&num=XXXX
            try:
                parsed = urlparse(full_url)
                qs = parse_qs(parsed.query)
                num = qs.get('num', [None])[0]
                tbl = qs.get('tbl', ['bbs31'])[0]
                if num:
                    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    full_url = f"{base}?tbl={tbl}&mode=VIEW&num={num}"
            except Exception:
                pass

            # 날짜는 <span> 중 두 번째 (예: 25.09.11)
            spans = td_left.find_all('span')
            if len(spans) >= 2:
                date_str = spans[1].text.strip()
            else:
                date_str = None

            if not date_str:
                continue

            # 날짜 형식 변환
            try:
                # '25.09.11' → '2025-09-11'
                year = int('20' + date_str.split('.')[0])
                month = int(date_str.split('.')[1])
                day = int(date_str.split('.')[2])
                date_obj = datetime(year, month, day)
                date_key = date_obj.strftime('%Y-%m-%d')
            except Exception:
                continue

            if DEBUG_LIST_ALL:
                print(f"{debug_count}\t{title}\t{date_key}\t{full_url}")
                debug_count += 1

            # 최근 5일 이내만 수집
            if date_obj >= five_days_ago:
                if not is_already_sent(title, date_key):
                    line = f"{count}\t{title}\t{date_key}\t{full_url}"
                    print(line)
                    msg += line + "\n"
                    save_sent(title, date_key)
                    count += 1

    # ==============================
    # 테스트 모드: 콘솔 출력만
    # ==============================
    if TEST_MODE:
        print(HEADER_TITLE)
        if msg:
            print("수집 결과:\n" + msg)
        else:
            print("최근 5일 이내 신규 공지사항 없음")
    else:
        # 실제 모드에서만 텔레그램 전송 (여기선 비활성화)
        if msg:
            msg = HEADER_TITLE + "\n" + msg
        pass

'''


//커서에서_가상환경만들기
#가상 환경을 사용하고, 모든 라이브러리를 다시 설치
python -m venv myenv #가상모둘생성
.\myenv\Scripts\activate #가상뮤듈실행. #명령 프롬프트 왼쪽에 (myenv)가 나타나면 성공적으로 활성화된 것
pip install playwright #가상환경에서 라이브러리설치


//크롤링_정보입력방식_"fiil()" vs "type()"
# 한 번에 전체 텍스트 입력_빠름
page.locator("#userName").fill("mardep")
page.locator("#pwd").fill("mardep00!!")

# 한 글자씩 타이핑_느림_'JavaScript 이벤트' 확실히 '트리거'됨
page.locator("#userName").type("mardep", delay=150)
page.locator("#pwd").type("mardep00!!", delay=150)


// DB 구조 + 데이터 확인
참고/검색 : SQLite DB 구조 및 데이터 확인 프로그램 PRD.md

코드
import sqlite3
from tkinter import filedialog
import tkinter as tk

# 파일 선택
root = tk.Tk()
root.withdraw()

file_path = filedialog.askopenfilename(
    title="DB 파일을 선택하세요",
    filetypes=[("SQLite DB", "*.db"), ("모든 파일", "*.*")]
)

if not file_path:
    print("파일을 선택하지 않았습니다.")
else:
    print("선택한 파일:", file_path)
    try:
        with sqlite3.connect(file_path) as conn:
            cur = conn.cursor()

            # 모든 테이블 조회
            cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [row[0] for row in cur.fetchall()]

            if not tables:
                print("\n❗️ DB에 테이블이 없습니다.")
            else:
                for table in tables:
                    print(f"\n📋 [테이블] {table}")

                    # 컬럼 구조 출력
                    cur.execute(f"PRAGMA table_info({table})")
                    columns = cur.fetchall()
                    for col in columns:
                        print(f"  - {col[1]} ({col[2]}) {'[PK]' if col[5] else ''}")
                    
                    # 데이터 출력
                    try:
                        cur.execute(f"SELECT * FROM {table}")
                        rows = cur.fetchall()
                        if rows:
                            print("\n📄 [데이터]")
                            for row in rows:
                                print("  ", row)
                        else:
                            print("\n📄 [데이터 없음]")
                    except Exception as e:
                        print(f"\n⚠️ {table} 테이블 조회 오류: {e}")

    except Exception as e:
        print("DB 파일 읽기 오류:", e)


//SSL우회

1. requests 사용시 동기방식
SSL 경고 비활성화 (임시 해결책)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 사용자 정의 requests 세션 설정 (SSL 검증 비활성화)
session = requests.Session()
session.verify = False

firecrawl의 실제 소스코드에서 SSL 비활성화
firecrawl의 실제 소스코드(firecrawl.py) 파일을 찾아
이제 이 파일에서 requests 관련 HTTP 호출 부분(예: requests.get, requests.post 등)에 verify=False 옵션을 직접 추가해야 합니다.
이 작업을 자동화하려면, firecrawl.py 파일에서 requests 호출 부분을 찾아 verify=False를 추가하는 코드를 바로 적용할 수 있습니다.

최초에는 firecrawl.py 가 없었잖아. 근데 ssl 오류 해결한 이후에는 파일이  왼쪽패널에 생겼네
정확하게 보셨습니다!
아주 중요한 차이점을 잘 짚으셨네요.
왜 firecrawl.py가 새로 생겼을까?
1. 최초 상태
원래는 firecrawl.py 파일이 프로젝트 폴더(왼쪽 패널)에 없었습니다.
대신, 파이썬의 site-packages(즉, 외부 패키지 설치 경로)에만 존재했죠.
여러분의 코드에서는 from firecrawl import FirecrawlApp 처럼 외부 패키지로서 사용했습니다.
2. SSL 오류 해결 과정
SSL 인증서 검증을 비활성화(verify=False)하려면 외부 패키지 내부의 코드를 직접 수정해야 했습니다.
하지만 site-packages는 VSCode 왼쪽 패널(작업 폴더)에서 바로 접근/수정이 어렵습니다.
그래서 직접 프로젝트 폴더로 firecrawl.py 파일을 복사해서 수정한 뒤, 이 파일이 프로젝트 폴더에 새로 생긴 것입니다.
3. 현재 상태
이제 프로젝트 폴더에 있는 firecrawl.py가 우선적으로 import됩니다.
즉, from firecrawl import FirecrawlApp 하면, site-packages가 아니라
프로젝트 폴더의 firecrawl.py가 사용됩니다. 이 파일에는 SSL 인증서 검증 비활성화 패치가 적용되어 있습니다.
결론
처음엔 없었지만, SSL 문제 해결을 위해 복사/수정해서 생긴 파일입니다.
이제 이 프로젝트는 내부의 firecrawl.py를 사용하므로 SSL 오류 없이 동작합니다.

만약 외부 패키지 버전을 업데이트하거나,
다른 프로젝트에서 firecrawl을 쓸 때는
동일한 패치가 필요할 수 있습니다.
추가로 궁금한 점,
파이썬 import 우선순위,
패키지 관리 등에 대해 궁금하면 언제든 질문해 주세요!


//SSL오류
## SSL 오류 해결 과정 PRD (재발 방지 문서)
### 1. 개요 (Introduction)

본 문서는 Python 환경에서 `SSL: CERTIFICATE_VERIFY_FAILED` 오류가 발생한 문제에 대한 분석, 해결 과정, 그리고 향후 유사 문제 발생 시의 재발 방지 및 해결 지침을 명시합니다.

**문제 현상:**
Python 스크립트 실행 중 `SSL: CERTIFICATE_VERIFY_FAILED` 오류가 발생하여 외부 API(Telegram API, LLM API 등)와의 SSL/TLS 통신이 실패함.

**원인 요약:**
Microsoft Store를 통해 설치된 Python 버전(예: Python 3.11)이 시스템의 `WindowsApps` 경로에 설치되면서, SSL 인증서 저장소 경로를 제대로 참조하지 못해 발생하는 인증서 유효성 검사 실패. 이는 Python 자체의 문제라기보다는 특정 설치 경로의 환경적 특성으로 인한 것이었음.

### 2. 문제 해결 과정 (Problem Resolution Process)

| 단계 | 설명 | 상세 내용 및 명령어 | 결과 |
| :--- | :--- | :--- | :--- |
| **2.1 기존 Python 환경 진단** | 오류 발생 시점의 Python 인터프리터 경로 확인 | `python --version` 및 오류 스택 트레이스에서 `C:/Users/KR/AppData/Local/Microsoft/WindowsApps/...` 경로 확인 | Python 3.11이 `WindowsApps` 경로에서 실행되고 있음을 확인. |
| **2.2 Microsoft Store Python 제거** | `WindowsApps` 경로의 Python이 문제를 일으킴을 인지하고, 해당 Python 제거 시도. | PowerShell (관리자 권한): `Get-AppxPackage *Python* | Remove-AppxPackage` 또는 특정 버전 제거: `Remove-AppxPackage -Package PythonSoftwareFoundation.Python.3.11_3.11.2544.0_x64__qbz5n2kfra8p0` | 제거 명령 실행. (즉시 반영되지 않을 수 있음) |
| **2.3 시스템 재부팅** | 제거 명령의 완전한 적용 및 시스템 환경 변수 업데이트를 위해 필수적으로 재부팅. | 컴퓨터 재부팅. | 재부팅 후 `설정 > 앱 > 설치된 앱`에서 `Python 3.11` 관련 항목이 사라졌는지 확인. |
| **2.4 Python 공식 설치 프로그램 재설치** | `WindowsApps` 경로가 아닌 표준 경로에 새로운 Python 버전 설치. | Python 공식 웹사이트에서 최신 안정 버전 (예: Python 3.12.7)의 설치 프로그램(`python.org`) 다운로드 및 설치. <br> **설치 시 `Add Python to PATH` 옵션 반드시 체크.** | Python 3.12.7이 `C:\Program Files\Python312`와 같은 표준 경로에 설치됨. |
| **2.5 IDE (Cursor) 환경 재설정** | IDE가 새로 설치된 Python 인터프리터를 참조하도록 설정. | Cursor IDE: `Ctrl + Shift + P` -> `Python: Select Interpreter` -> `C:\Program Files\Python312\python.exe` 선택. <br> IDE 재시작. | Cursor IDE가 Python 3.12.7을 사용함을 확인. (터미널에서 `python --version` 재확인) |
| **2.6 필수 라이브러리 재설치** | 새 Python 환경에 필요한 라이브러리(`python-telegram-bot`, `python-dotenv`, `agents` 등) 설치. | Cursor IDE 터미널: <br> `pip install python-telegram-bot` <br> `pip install python-dotenv` <br> `pip install agents` (만약 설치되지 않았다면) | 모든 라이브러리가 새 Python 환경에 성공적으로 설치됨. |
| **2.7 코드 수정 및 재검증** | 이전 오류들(`SyntaxError`, `TypeError`, `NameError`)을 해결하며 코드 로직 및 `agents` 라이브러리 사용법을 올바르게 수정. | `async/await` 구조, `Runner.run()` 인자, `@function_tool` 데코레이터 사용법 등 수정. | 코드 실행 성공 및 텔레그램 메시지 전송 확인. |

### 3. 근본 원인 분석 (Root Cause Analysis)

`SSL: CERTIFICATE_VERIFY_FAILED` 오류의 직접적인 원인은 Python이 SSL/TLS 통신을 위해 사용하는 **인증서 번들(CA Certificates)을 올바르게 찾거나 로드하지 못했기 때문**입니다. Microsoft Store를 통해 설치된 Python 버전은 `WindowsApps`라는 특수 권한 및 관리 경로에 위치하며, 이 경로의 특성상 일반적인 Python 설치 방식과는 다른 환경 변수 설정이나 인증서 경로 참조 문제를 일으킬 수 있습니다. 표준 설치 경로(`Program Files`)에 설치된 Python은 일반적으로 이러한 문제를 겪지 않습니다.

### 4. 재발 방지 대책 (Prevention Measures)

향후 유사한 SSL 오류 및 환경 설정 문제를 방지하기 위해 다음 지침을 준수합니다.

* **4.1 Python 설치 시 주의:**
    * **Microsoft Store를 통해 Python을 설치하지 않습니다.**
    * **항상 Python 공식 웹사이트(`python.org`)에서 설치 프로그램을 다운로드하여 사용합니다.**
    * 설치 시 **`Add Python to PATH` 옵션을 반드시 체크**하여 환경 변수 설정을 자동화합니다.
    * 가능하다면 `C:\Program Files\PythonXX`와 같은 표준 경로에 설치합니다.
* **4.2 가상 환경(Virtual Environments) 사용 의무화:**
    * 각 프로젝트마다 독립적인 Python 가상 환경(venv, conda 등)을 생성하여 사용합니다.
    * **설치 지침:**
        ```bash
        # 프로젝트 폴더로 이동
        cd E:\임시_삭제\새 폴더

        # 가상 환경 생성 (예: .venv 폴더)
        python -m venv .venv

        # 가상 환경 활성화
        # Windows PowerShell:
        .venv\Scripts\Activate.ps1
        # Windows Command Prompt:
        .venv\Scripts\activate.bat
        ```
    * 가상 환경 활성화 후 모든 `pip install` 명령을 실행합니다. 이는 시스템 전체 Python 환경을 오염시키지 않고, 프로젝트별로 필요한 라이브러리 버전을 독립적으로 관리할 수 있게 합니다.
* **4.3 `.env` 파일 및 환경 변수 관리:**
    * API 키, 토큰 등 민감한 정보는 `.env` 파일을 사용하여 관리하고, `python-dotenv` 라이브러리로 로드합니다.
    * `.env` 파일은 버전 관리 시스템(Git)에 포함시키지 않도록 `.gitignore`에 추가합니다.
* **4.4 오류 메시지 분석 습관화:**
    * 새로운 오류 발생 시, 스택 트레이스의 **가장 마지막 줄**부터 확인하여 실제 오류 메시지를 파악합니다.
    * 오류 메시지에 포함된 힌트(예: `Did you mean: 'filters'`)를 적극 활용합니다.
    * `TypeError: missing required positional argument`와 같은 메시지는 라이브러리 사용법(매개변수 이름/순서) 변경을 의미할 수 있음을 인지합니다.

### 5. 후속 조치 (Follow-up Actions)

* 현재 작업이 완료된 후, 해당 프로젝트에 가상 환경을 적용하여 `.env` 파일과 함께 사용할 수 있도록 리팩토링합니다.
* 주기적으로 사용 중인 라이브러리들의 공식 문서를 확인하여 주요 버전 업데이트에 따른 변경 사항(특히 API 사용법)을 미리 파악합니다.


googleapiclient 문제해결 SSL
[문제 및 해결과정 문서(PRD)]
1. 문제(Problem)
현상:
googleapiclient를 이용해 YouTube Data API를 호출할 때
ssl.SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate in certificate chain
오류가 발생함.
환경:
Windows 환경의 로컬 파이썬 실행 시 발생
Colab 등 클라우드 환경에서는 정상 동작
2. 원인 분석
파이썬이 HTTPS 통신 시 SSL 인증서 검증을 수행하는데,
로컬 환경의 네트워크(회사/학교/공공기관 등) 또는 파이썬 인증서 번들 문제로 인해 자체 서명 인증서(self-signed certificate)가 포함된 경우 검증에 실패함.
googleapiclient는 내부적으로 httplib2 라이브러리를 사용하며, 이 라이브러리의 기본 설정에서는 SSL 인증서 검증을 수행함.
3. 기존 시도
ssl._create_default_https_context = ssl._create_unverified_context 코드 추가
→ httplib2에는 적용되지 않아 실패
certifi 재설치, Install Certificates 스크립트 실행
→ 환경에 따라 여전히 실패
4. 최종 해결 방법(Resolution)
핵심:
httplib2.Http(disable_ssl_certificate_validation=True) 옵션을 사용하여
SSL 인증서 검증을 완전히 비활성화함.
build() 함수에 http 인자를 명시적으로 전달하여
모든 API 호출에서 SSL 검증을 우회함.
적용 코드 예시
    import httplib2
    from googleapiclient.discovery import build
    from datetime import datetime

    API_KEY = 'YOUR_API_KEY'

    def youtube_search_today(query, max_results=10):
        http = httplib2.Http(disable_ssl_certificate_validation=True)
        youtube = build('youtube', 'v3', developerKey=API_KEY, http=http)
        # ... 이하 동일 ...
5. 결과
SSL 인증서 오류 없이 정상적으로 YouTube Data API 호출 가능
Colab/로컬 환경 모두에서 동일하게 동작
6. 주의사항
보안상 위험:
SSL 인증서 검증을 끄는 것은 보안상 안전하지 않으므로,
반드시 신뢰할 수 있는 네트워크/환경에서만 사용해야 함.
운영(Production) 환경에서는 권장하지 않음!



2. 비동기 방식
import aiohttp
import asyncio
import ssl

# SSL 우회 세팅
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE






//텔레그램봇
# Send the message via Telegram
import telepot
bot = telepot.Bot(token='6250305411:AAHWIpJDIUU57x_cFORKGsPwecQq_QYlWmw')
bot.sendMessage(chat_id=752516623, text=msg)
print(msg)




// 팝업으로 파일 선택
import tkinter as tk
from tkinter import filedialog

# 팝업으로 파일 선택
root = tk.Tk()
root.withdraw()  # Tk 창 숨기기

file_path = filedialog.askopenfilename(
    title=" 파일을 선택하세요",
    filetypes=[("SQLite DB", "*.db"), ("모든 파일", "*.*")]
)


// db파일읽는법
import sqlite3
from tkinter import filedialog
import tkinter as tk

# 팝업으로 파일 선택
root = tk.Tk()
root.withdraw()  # Tk 기본 창 숨김

file_path = filedialog.askopenfilename(
    title="DB 파일을 선택하세요",
    filetypes=[("SQLite DB", "*.db"), ("모든 파일", "*.*")]
)

if not file_path:
    print("파일을 선택하지 않았습니다.")
else:
    print("선택한 파일:", file_path)
    try:
        with sqlite3.connect(file_path) as conn:
            cur = conn.cursor()
            cur.execute("SELECT title FROM sent_books")
            rows = cur.fetchall()
            print("DB에 저장된 제목 목록:")
            for row in rows:
                print("-", row[0])
    except Exception as e:
        print("DB 파일 읽기 오류:", e)




// Awesome CursorRules
// A curated list of awesome .cursorrules files for enhancing Cursor AI experience

// General guidelines
Always use Markdown for documentation and README files
Maintain the existing structure of the README.md file

// README.md structure
Maintain the following structure in the README.md file:
  1. Title and Awesome badge
  2. Logo
  3. Short description
  4. "Why .cursorrules?" section
  5. Table of Contents
  6. Rules section
     - Frontend Frameworks and Libraries
     - Backend and Full-Stack
     - Mobile Development
     - CSS and Styling
     - State Management
     - Database and API
     - Testing
     - Build Tools and Development
     - Language-Specific
     - Other
  7. How to Use section
  8. Contributing section
  9. License section

// Organization of rules
Organize .cursorrules files into the following main categories within the 'rules' directory:
  - Frontend Frameworks and Libraries
  - Backend and Full-Stack
  - Mobile Development
  - CSS and Styling
  - State Management
  - Database and API
  - Testing
  - Build Tools and Development
  - Language-Specific
  - Other
Place each .cursorrules file directly in the 'rules' folder
The folder name for each .cursorrules file should describe the category and content of the file
Refer to the README in each folder for guidance on naming conventions and descriptions

// Naming and formatting
Use descriptive names for .cursorrules files and their folders, following the pattern: 'technology-focus-cursorrules-prompt-file'
Maintain alphabetical order within each category in the README.md file
Use consistent formatting for list items in the README.md file

// Content guidelines
When creating or editing .cursorrules files, focus on project-specific instructions and best practices
Include comments in .cursorrules files to explain complex rules or provide context
Use clear and concise language in all documentation and .cursorrules files
Provide context on what you're building, style guidelines, or info on commonly-used methods

// Optional README for credit and description
Each .cursorrules file may have an accompanying README.md file in its folder
Use this README to provide credit to the original author and a brief description of the .cursorrules file's purpose

// Maintenance and updates
Update the README.md file when adding new .cursorrules files, placing them in the correct category
Ensure all links in the README.md file are relative and correct
When updating the README.md, ensure the table of contents remains accurate
When adding new categories, update both the 'Contents' and 'Rules' sections of the README.md
Regularly review and update categorization as the repository grows

// Best practices
Maintain consistency in capitalization and punctuation throughout the repository
When referencing Cursor AI, always use the correct capitalization and spacing
When adding examples or explanations, focus on practical use cases for Cursor AI users
If a .cursorrules file fits multiple categories, place it in the most relevant one and cross-reference in others if necessary
Keep the 'Other' category for .cursorrules files that don't fit neatly into the main categories

// Additional insights
.cursorrules files are repo-specific "Rules for AI"
.cursorrules files should be placed in the root of the repository
The content of .cursorrules files will be appended to the global "Rules for AI" settings in Cursor
Focus on providing repo-level context and guidelines, not just general coding practices
.cursorrules can include information about project structure, architectural decisions, and commonly used libraries or methods
Consider including rules for handling specific file types or coding patterns unique to your project
Rules can cover both code generation and code understanding aspects for Cursor AI





//PRP 프레임워크 생성 방법
PRP 프레임워크는 바로 이러한 컨텍스트 엔지니어링을 통해 AI 코딩 어시스턴트가 타당한 솔루션을 한 번에 제대로 구현할 수 있도록 필요한 컨텍스트를 제공하는 것을 목표로 합니다.
PRP 프레임워크는 크게 다음의 세 가지 단계로 이루어집니다:
1단계: initial.md 작성 (무엇을 만들지, 어떤 도구를 쓸지, 제약사항 등 구체적으로 명시)
• 목적: 사용자가 만들고자 하는 애플리케이션이나 에이전트를 상세하게 설명하는 파일입니다. 이 파일은 이후 PRP를 생성하는 데 사용되는 핵심 입력이 됩니다.
• 주요 구성 요소: initial.md 템플릿에는 AI 코딩 어시스턴트가 에이전트를 정확하게 이해하고 구축하는 데 필요한 모든 구체적인 정보가 포함됩니다.
    ◦ 기능 (Feature): 구축하려는 AI 에이전트의 전체적인 목표를 설명합니다.
    ◦ 도구 (Tools): 에이전트가 수행할 수 있도록 하려는 특정 기능(예: Brave API를 사용한 웹 검색, 이메일 초안 작성 등)을 구체적으로 명시합니다.
    ◦ 종속성 (Dependencies): API 키, 데이터베이스 연결 등 도구에 필요한 요소들을 정의합니다.
    ◦ 시스템 프롬프트 (System Prompt): 에이전트의 동작을 안내하기 위한 일반적인 설명이나 전체 시스템 프롬프트를 작성하는 공간입니다.
    ◦ 예시 (Examples): 유사한 과거 프로젝트, 온라인 리소스 또는 관련 문서에서 가져온 구체적인 코드 예시를 포함합니다. 이는 AI 코딩 어시스턴트에게 매우 강력한 컨텍스트를 제공하며, 때로는 문서보다 더 효과적일 수 있습니다.
    ◦ 참조 문서 (Documentation): 공식 문서 링크를 포함하여 AI 코딩 어시스턴트가 특정 API(예: Gmail, Brave)를 올바르게 사용하는 방법을 이해하고 도구를 제대로 구축하는 데 필수적인 정보를 제공합니다. 이는 AI 코딩 어시스턴트의 환각(hallucination)을 크게 줄이는 데 도움이 됩니다.
    ◦ 고려 사항 (Considerations/Gotchas): 환경 변수 관리 방식이나 AI 코딩 어시스턴트가 과거에 자주 오류를 범했던 부분 등, 개발자가 특별히 유의해야 할 지점들을 명시하여 동일한 실수를 반복하지 않도록 안내합니다.
2단계: generate (AI가 base PRP와 결합해 PRP 생성)
• 목적: initial.md에 담긴 상세한 설명을 바탕으로 AI 코딩 어시스턴트가 **완전한 컨텍스트를 갖춘 PRP(Product Requirements Prompt)**를 생성하도록 돕는 단계입니다.
• 작동 방식:
    ◦ 사용자는 /generate podantic AI PRP와 같은 명령어를 사용하여 AI 코딩 어시스턴트에게 initial.md 파일을 인수로 전달합니다.
    ◦ AI 코딩 어시스턴트는 이 initial.md와 '기본 PRP(Base PRP)' 템플릿, 그리고 특정 사용 사례에 맞춰 튜닝된 '전역 규칙(Global Rules, 예: claw.md)' 등을 결합하여 완전한 컨텍스트를 가진 PRP를 만들어냅니다. 기본 PRP 템플릿에는 참조할 문서, 원하는 코드 구조, 주의 사항, 모범 사례 및 개발 패턴 등이 포함됩니다.
    ◦ 이 과정에서 AI는 사용자를 대신하여 많은 연구와 아키텍팅 작업을 수행하며, PRP에 필요한 정보들을 단계별로 생각하고 구성합니다.
• 결과: 최종적으로 PRPs 폴더에 새로운 PRP 파일이 생성됩니다. 이 PRP는 온라인 리소스, 기존 예시 폴더의 예시, 그리고 문서가 아름답게 결합된 형태입니다.
3단계: execute (PRP 바탕으로 실제 에이전트 생성)
• 목적: 2단계에서 생성된 완성된 PRP를 바탕으로 실제 AI 에이전트의 구현 코드를 생성하는 단계입니다.
• 작동 방식:
    ◦ PRP를 실행하기 전에, 이전 대화의 오래된 컨텍스트가 남아있지 않도록 **AI 코딩 어시스턴트의 대화 기록을 지우는 것(clear conversation)**이 중요합니다.
    ◦ 사용자는 /execute podantic AI PRP와 같은 명령어를 사용하여 PRP 파일의 경로를 인수로 전달합니다.
    ◦ AI 코딩 어시스턴트는 이 광범위한 지침 세트와 풍부한 컨텍스트를 바탕으로 에이전트의 코드를 생성합니다. 이 과정 또한 상당한 시간이 소요될 수 있습니다.
• 중요한 고려 사항:
    ◦ 결과물의 유효성 검증은 매우 중요합니다. AI 코딩 어시스턴트의 결과물을 맹목적으로 신뢰해서는 안 됩니다. 개발자는 생성된 코드를 직접 검토하고 이해하며, 필요한 경우 단위 테스트 작성 및 모든 테스트 통과까지 반복하도록 지시하는 것과 같은 "유효성 검증 게이트(validation gates)"를 PRP에 포함하여 코드의 품질을 검증해야 합니다.
    ◦ 완벽하게 한 번에 완성되지 않을 수 있으며, 생성된 PRP나 에이전트 코드에 대해 반복적인 수정 및 개선(iteration) 과정이 필요할 수 있습니다.
이 3단계 프로세스를 통해 개발자는 AI 코딩 어시스턴트의 강력한 기능을 활용하여 복잡한 AI 에이전트를 효율적이고 신뢰할 수 있게 구축할 수 있습니다.


#스케쥴러사용
1.배치파일생성

2.스케쥴러사용

PRD: 배치 파일 및 파이썬 스크립트 실행 오류 해결 사례
    1. 개요 (Overview)
    본 문서는 Windows 환경에서 배치 파일(.bat)을 통해 파이썬 스크립트(.py)를 실행할 때 발생했던 두 가지 주요 오류, 즉 "파일 이름, 디렉터리 이름 또는 볼륨 레이블 구문이 잘못되었습니다." 오류 와 UnicodeEncodeError 의 발생 원인 및 해결 과정을 상세히 기록합니다. 이 문서는 향후 유사한 문제 발생 시 비개발자도 쉽게 문제를 진단하고 해결할 수 있도록 돕거나, AI 모델이 문제 해결 과정을 학습하는 데 활용될 수 있습니다.

    2. 문제 정의 (Problem Definition)
    사용자는 E:\AI경진대회 경로에 위치한 run_bot.bat 배치 파일을 더블클릭하여 같은 폴더의 항공권.py 파이썬 스크립트를 실행하려고 했습니다. 그러나 스크립트는 정상적으로 실행되지 않고 다음 두 가지 유형의 오류가 순차적으로 발생했습니다.

    2.1. 첫 번째 오류: "파일 이름, 디렉터리 이름 또는 볼륨 레이블 구문이 잘못되었습니다."
    발생 상황: run_bot.bat 파일을 더블클릭하여 실행했을 때 콘솔 창에 이 오류 메시지가 반복적으로 출력되었고, 파이썬 스크립트는 전혀 실행되지 않았습니다. 배치 파일 내의 pause 명령어로 인해 콘솔 창은 닫히지 않고 오류 메시지를 계속 보여주었습니다.

    초기 진단:

    파이썬 실행 파일 경로(C:\Program Files\Python312\python.exe 또는 C:\Users\KR\AppData\Local\Microsoft\WindowsApps\python.exe)는 정확했으며, 스크립트(항공권.py) 파일도 지정된 경로에 존재했습니다.

    핵심 단서: 명령 프롬프트(CMD)를 직접 열고 동일한 파이썬 실행 명령을 수동으로 입력했을 때는 스크립트가 정상적으로 실행되었습니다. 이는 파이썬 스크립트 자체나 파이썬 환경의 문제는 아니며, 배치 파일이 실행되는 방식이나 배치 파일 자체의 문제임을 시사했습니다.

    가장 유력한 원인: 배치 파일의 인코딩 문제. 특히 한글 경로(E:\AI경진대회)가 포함된 상황에서 윈도우 배치 파일은 일반적으로 ANSI 인코딩을 사용해야 합니다.

    2.2. 두 번째 오류: UnicodeEncodeError: 'cp949' codec can't encode character '\u2705' in position 0: illegal multibyte sequence
    발생 상황: 첫 번째 오류 해결 후 run_bot.bat을 실행했을 때, 파이썬 스크립트가 실행되는 것처럼 보였으나, 콘솔 출력이나 로그 파일에서 해당 UnicodeEncodeError가 발생하며 스크립트 실행이 중단되었습니다.

    진단: 오류 메시지는 파이썬 스크립트 내에서 특정 유니코드 문자(예: \u2705 즉 ✅ 이모지)를 표준 출력(콘솔)으로 print 하려고 할 때, 윈도우의 기본 인코딩인 cp949 (한글 Windows 코드 페이지)가 해당 문자를 인코딩할 수 없어서 발생했음을 명확히 보여주었습니다.

    3. 해결 과정 (Solution Process)
    단계별로 문제를 진단하고 해결했던 과정을 설명합니다.

    3.1. 첫 번째 오류 해결: 배치 파일 인코딩 "ANSI"로 변경
    문제 식별 단계:

    사용자가 Notepad++에서 run_bot.bat 파일을 열고 인코딩 설정을 보여주는 스크린샷을 제공했습니다. 이 스크린샷에서 UTF-8-BOM으로 인코딩되어 있음이 확인되었습니다.

    이는 윈도우 배치 파일에서 한글 경로를 포함할 때 자주 발생하는 문제의 원인으로 지목되었습니다. 배치 파일은 BOM(Byte Order Mark)을 올바르게 처리하지 못하고 이를 파일 내용의 일부로 오해하여 구문 분석 오류를 일으킵니다.

    해결책 적용:

    run_bot.bat 파일을 Notepad++로 엽니다.

    메뉴에서 인코딩(Encoding) -> ANSI로 변환(Convert to ANSI)을 선택합니다.

    파일(File) -> 저장(Save)을 클릭하여 변경 사항을 적용합니다. (다른 이름으로 저장 아님).

    결과: 이 조치 후, run_bot.bat을 더블클릭했을 때 "파일 이름, 디렉터리 이름 또는 볼륨 레이블 구문이 잘못되었습니다." 오류 메시지는 더 이상 나타나지 않았습니다. 대신 파이썬 스크립트 실행 시 발생하는 새로운 오류가 감지되기 시작했습니다.

    3.2. 두 번째 오류 해결: PYTHONIOENCODING 환경 변수 설정
    문제 식별 단계:

    첫 번째 오류 해결 후, 배치 파일 실행 시 UnicodeEncodeError가 발생한다는 것이 telegram_bot_output.txt 파일의 내용을 통해 확인되었습니다.

    오류 메시지는 특정 유니코드 문자(\u2705)를 cp949 코덱이 인코딩할 수 없음을 명확히 밝혔습니다.

    해결책 적용:

    run_bot.bat 파일을 Notepad++로 다시 엽니다. (이때도 인코딩이 ANSI로 잘 되어 있는지 다시 확인합니다.)

    파이썬 실행 명령문 바로 위에 다음 줄을 추가합니다.

    코드 스니펫

    set PYTHONIOENCODING=utf-8
    (완성된 배치 파일 내용은 다음과 같음)

    코드 스니펫

    @echo off
    REM Change directory to script location
    cd /d "E:\AI경진대회"

    REM Set Python I/O encoding to UTF-8
    set PYTHONIOENCODING=utf-8

    REM Start time log
    echo %date% %time% >> "telegram_bot_log.txt"

    REM Run Python script and capture all output (stdout & stderr) to a single file
    REM Also display output on screen for debugging
    "C:\Program Files\Python312\python.exe" "항공권.py" > "telegram_bot_output.txt" 2>&1

    REM End time log
    echo %date% %time% (End) >> "telegram_bot_log.txt"
    pause
    수정된 배치 파일을 Notepad++에서 ANSI 인코딩으로 다시 저장합니다.

    결과: 이 조치 후, run_bot.bat을 더블클릭했을 때 파이썬 스크립트가 정상적으로 실행되었고, 웹 스크래핑 및 텔레그램 메시지 전송까지 성공적으로 완료되었습니다.

    4. 비개발자 및 AI를 위한 설명 (Explanation for Non-Developers & AI)
    4.1. "파일 이름, 디렉터리 이름 또는 볼륨 레이블 구문이 잘못되었습니다." 오류 (첫 번째 오류)
    비유: 워드 프로세서(예: 한글, MS Word)에서 문서를 작성하고 저장할 때, 어떤 파일 형식(예: .docx, .hwp, .txt)으로 저장할지 선택하는 것과 비슷합니다. 배치 파일도 컴퓨터가 이해할 수 있는 특정 '언어' 형식으로 저장되어야 합니다. Windows의 명령 프롬프트는 오래된 프로그램이라서, 기본적으로 "ANSI"라는 형식을 가장 잘 이해합니다.

    문제 발생 원인: 배치 파일을 Notepad++와 같은 다른 프로그램에서 "UTF-8-BOM"이라는 형식으로 저장하면, 컴퓨터는 이 파일이 어떤 언어 형식인지 제대로 파악하지 못하고 혼란스러워합니다. 특히 파일 맨 앞에 있는 숨겨진 '표시'(BOM)를 이상한 기호로 인식하여, 파일 내용이 잘못되었다고 판단하는 것입니다. 한글 경로가 있으면 이런 문제가 더 심해집니다.

    해결책: 배치 파일을 저장할 때 반드시 "ANSI" 형식으로 저장해야 합니다. Notepad++에서는 인코딩 메뉴에서 ANSI로 변환을 선택한 후 저장을 누르면 됩니다.

    4.2. UnicodeEncodeError (두 번째 오류)
    비유: 이것은 번역 문제와 비슷합니다. 여러분이 한국어로 말하는데 상대방이 한국어를 못하고 영어만 아는 경우를 상상해 보세요. 파이썬 스크립트는 이모지(그림 문자)와 같은 다양한 언어의 문자를 사용하려고 하는데, 윈도우의 명령 프롬프트는 기본적으로 오래된 한국어(CP949)만 이해하도록 설정되어 있습니다. 그래서 스크립트가 "✅" 같은 문자를 출력하려고 하면, 명령 프롬프트가 "나는 이 문자를 모릅니다! 내 언어로는 번역할 수 없습니다!"라고 거부하는 것입니다.

    문제 발생 원인: 파이썬 스크립트가 현대적인 유니코드 문자(예: 이모지)를 사용하려고 하지만, 스크립트가 실행되는 윈도우 환경의 명령 프롬프트는 기본적으로 cp949라는 구식 인코딩(글자 체계)을 사용하고 있기 때문입니다. cp949는 모든 유니코드 문자를 표현할 수 없습니다.

    해결책: 배치 파일 안에 set PYTHONIOENCODING=utf-8이라는 명령을 추가합니다. 이 명령은 파이썬 스크립트에게 "앞으로는 글자를 주고받을 때 cp949 말고, 더 많은 글자를 이해할 수 있는 utf-8이라는 최신 언어 형식을 사용해!"라고 지시하는 것과 같습니다. 이렇게 하면 파이썬 스크립트가 이모지 등을 문제없이 출력할 수 있게 됩니다.

    5. 결론 (Conclusion)
    이번 문제 해결 과정을 통해, 겉으로 보이는 "구문 오류"가 단순히 코드의 문제가 아니라, 파일 인코딩과 환경 변수 설정이라는 심층적인 시스템 환경 문제에서 비롯될 수 있음을 확인했습니다. 특히 윈도우 환경에서 한글 경로를 사용하는 경우 배치 파일의 인코딩이 중요하며, 파이썬 스크립트에서 유니코드 문자를 다룰 때는 입출력 인코딩을 명시적으로 설정해주는 것이 필수적임을 알 수 있었습니다.

    이 경험이 향후 유사한 문제 발생 시 빠르고 정확한 진단과 해결에 큰 도움이 될 것입니다.




//pythoanywhere 파이썬애니웨어 #가상환경

/home/mardep/.virtualenvs/my-playwright-env/bin/python /home/mardep/.virtualenvs/my-playwright-env/bin/flight.py

/home/mardep/이 앞뒤에 두번중복임. 왜?? 각 역할이 다름. 각각 가상환경과 실행파일위치를 지정해줌
앞쪽의 /home/mardep/ 은 가상환경 위치
뒤쪽의 /home/mardep/ 은 실행파일 위치

playwright 사용법
bach console 연다

