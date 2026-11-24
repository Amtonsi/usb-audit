"""Проверяем автономный отчёт в Chromium, не устанавливая сборщик USB-Audit."""
import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
BROWSER_JS = r"""
function check(value,message){if(!value)throw new Error(message)}
function rows(id){return document.querySelectorAll('#'+id+' tbody tr').length}
function find(text){$('search').value=text;filterReport()}
try{
    if(document.title==='Архив'){
        check(rows('devices')===0 && rows('archives')===1,'Действия с архивами без носителей');
        check(!$('archive-scope-note').hidden && $('outgoing').hidden,'Отдельный архив');
    }else{
        check(rows('sessions')===2 && rows('transfers')===4,'Разделение сеансов и дедупликация');
        check(rows('archives')===20 && $('archive-pages').querySelectorAll('button').length===2,'Пагинация действий');
        $('archive-pages').querySelectorAll('button')[1].click();
        check(rows('archives')===1,'Вторая страница действий');
        check($('transfers').textContent.includes('Содержимое совпало') && $('transfers').textContent.includes('Вероятный перенос'),'Разные основания');
        check($('transfers').querySelector('details').textContent.includes('a'.repeat(64)),'Отображение SHA-256');
        const observed=[...$('transfers').tBodies[0].rows].find(row=>row.textContent.includes('наблюдение.txt'));
        check(observed && observed.cells[3].textContent.includes('Уведомление папки назначения · Создание файла') &&
            observed.cells[3].textContent.includes('b'.repeat(64)) &&
            observed.cells[4].textContent.includes('Только чтение с носителя'),'Путь по уведомлению и автор чтения');
        const possible=[...$('transfers').tBodies[0].rows].find(row=>row.textContent.includes('большой.bin'));
        check(possible && possible.cells[3].textContent.includes('Возможный перенос') &&
            possible.cells[3].textContent.includes('Появился одноимённый файл') && !possible.querySelector('details') &&
            possible.cells[4].textContent.includes('Автор записи неизвестен'),'Уведомление без хеша и автор чтения');
        check(!$('transfers').querySelector('img') && !$('archives').querySelector('img'),'Безопасный вывод путей и результатов');
        find('получено');check(rows('transfers')===1 && rows('sessions')===1 && rows('archives')===0,'Поиск по назначению');
        find('архивариус');check(rows('devices')===0 && rows('archives')===1,'Независимый поиск по архивам');
        find('');$('from').value='2031-01-01';filterReport();
        check(rows('devices')===0 && rows('archives')===0,'Ограничение по датам');
        $('reset').click();$('sessions').querySelectorAll('.rowbutton')[1].click();
        check(rows('transfers')===0 && !$('empty-transfers').hidden,'Старый сеанс без переносов');
        $('file-mode').value='all';filterReport(true);
        check(rows('files')===1 && $('files').textContent.includes('Только чтение'),'Обычное чтение сохранено');
        check($('alarm').hidden,'Новые типы записей распознаны');
    }
    document.documentElement.dataset.qa='passed';
}catch(err){ document.documentElement.dataset.qa='failed'; document.documentElement.dataset.reason=err.message; }
"""


def encoded(data):
    return base64.b64encode(data.encode("utf-8")).decode("ascii")


def local_browser():
    for env, rel in (("PROGRAMFILES", "Google/Chrome/Application/chrome.exe"),
                     ("PROGRAMFILES(X86)", "Microsoft/Edge/Application/msedge.exe")):
        browser = Path(os.environ.get(env, "")) / rel
        if browser.is_file():
            return str(browser)
    for name in ("chromium", "google-chrome", "msedge"):
        if shutil.which(name):
            return shutil.which(name)
    raise RuntimeError("Для проверки требуется установленный Chrome, Edge или Chromium.")


def render(browser, folder, events, scope):
    template = (ROOT / "src/viewer.html").read_text("utf-8")
    records = "\n".join(json.dumps(event, ensure_ascii=False) for event in events)
    meta = {"time": "2026-11-26T01:00:00Z", "scope": scope, "demo": True, "problems": []}
    blocks = (f'<script type="application/octet-stream" class="log-source" data-name="{encoded("тест")}">{encoded(records)}</script>'
              f'<script type="application/octet-stream" id="report-meta">{encoded(json.dumps(meta))}</script>')
    if scope == "archive":
        template = template.replace("<title>Журнал USB</title>", "<title>Архив</title>")
    file = folder / (scope + ".html")
    file.write_text(template.replace("<!-- USB-AUDIT-DATA -->", blocks)
                    .replace("</body>", "<script>" + BROWSER_JS + "</script></body>"), encoding="utf-8")
    flags = [browser, "--headless=new", "--disable-background-networking", "--disable-extensions",
             "--no-first-run", "--no-default-browser-check", "--dump-dom",
             "--user-data-dir=" + str(folder / ("profile-" + scope)), file.as_uri()]
    result = subprocess.run(flags, capture_output=True, timeout=60)
    dom = result.stdout.decode("utf-8")
    if result.returncode or 'data-qa="passed"' not in dom.split("<head>", 1)[0]:
        raise AssertionError(dom.split("<head>", 1)[0] + result.stderr.decode("utf-8", "replace")[-400:])


def main():
    legacy = {"type": "connect", "time": "2026-11-23T08:00:00Z", "session": "old", "deviceId": "USB-DEMO"}
    current = dict(legacy, session="new", time="2026-11-24T08:00:00Z")
    read = dict(legacy, type="file", action="Только чтение", accessMask="0x1", path=r"E:\old.txt")
    transfer = dict(current, type="transfer", evidence="matchingContent", sha256="a" * 64,
                    path=r"E:\отчёт.txt", destination=r"C:\получено\<img>.txt", sourceRecordId=11,
                    destinationRecordId=12, logEpoch="sample")
    other = dict(transfer, evidence="pairedAccess", destination=r"C:\архив\текст.txt",
                 sourceRecordId=21, destinationRecordId=22, sha256=None)
    observed = dict(current, type="transfer", evidence="observedMatchingContent", sha256="b" * 64,
                    uid="observed-demo", path=r"E:\наблюдение.txt", destination=r"C:\папка\наблюдение.txt",
                    sourceRecordId=31, destinationChange="Created", process="explorer.exe", account="usb-reader")
    possible = dict(observed, uid="create-demo", evidence="observedCreation", sha256=None,
                    path=r"E:\большой.bin", destination=r"C:\папка\большой.bin", sourceRecordId=32,
                    sourceBytes=5000000, destinationBytes=5000000)
    archive = {"type": "archiveAudit", "time": "2026-11-24T09:10:00Z", "action": "Удаление",
               "result": "<img> Отказано", "path": r"C:\Audit\Archive\usb-demo.jsonl", "source": "Windows Security",
               "account": "Архивариус", "recordId": 50, "logEpoch": "sample"}
    archive_more = [dict(archive, account="Тест", recordId=i) for i in range(51, 71)]
    with tempfile.TemporaryDirectory(prefix="usb-audit-viewer-") as temp:
        browser, folder = local_browser(), Path(temp)
        render(browser, folder, [archive], "archive")
        render(browser, folder, [legacy, read, current, transfer, other, dict(transfer), observed, dict(observed), possible,
                                 archive, dict(archive), *archive_more], "all")
    print("Пройдены проверки отчёта для двух версий записей, фильтров, пагинации и отдельного архива.")


if __name__ == "__main__":
    main()
