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
    }else if(meta.scope==='shell'){
        const transfers=[...$('transfers').tBodies[0].rows];
        const into=transfers.find(r=>r.cells[0].textContent.includes('Компьютер → USB'));
        const out=transfers.find(r=>r.cells[0].textContent.includes('USB → компьютер'));
        check(transfers.length===2 && into && out,'Оба направления операций Проводника');
        check(into.cells[1].textContent==='C:\\Папка\\ноль.txt' && into.cells[2].textContent==='H:\\ноль.txt' &&
              out.cells[1].textContent==='H:\\ноль.txt' && out.cells[2].textContent==='D:\\Приём\\ноль.txt','Исходный и конечный пути');
        check(into.cells[3].textContent.includes('Команда «Копировать»') && out.cells[3].textContent.includes('Команда «Переместить»') &&
              out.cells[3].textContent.includes('Shell-Core 18905') && out.cells[3].textContent.includes('по NTFS') &&
              out.cells[4].textContent.includes('PID 321'),'Команда, проверка NTFS и источник события Windows');
        check(!out.textContent.includes('SHA-256') && !into.textContent.includes('Содержимое совпало'),'Без хеша не заявляется проверка содержимого');
        check(rows('files')===1 && $('files').textContent.includes('Копирование на USB из каталога') &&
              $('files').textContent.includes('C:\\Папка') && !$('files').textContent.includes('Совпали события чтения'),'Команда видна при утраченном начале сеанса');
        const cmd=$('shell-commands').tBodies[0].rows[0];
        check(rows('shell-commands')===1 && cmd.cells[1].textContent==='H:\\частный.txt' &&
              cmd.cells[2].textContent==='C:\\Private\\частный.txt' && cmd.cells[3].textContent.includes('Результат не подтверждён'),
              'Непроверенный результат в отдельной строке с исходником и назначением');
        check($('total-files').textContent==='1' && $('transfer-caption').textContent==='2 из 2','Команды исключены из итогов');
        find('Private');check(rows('shell-commands')===1 && !$('command-results').hidden && rows('files')===0 &&
              rows('transfers')===0 && rows('devices')===1 && $('empty-transfers').textContent.includes('Команды Проводника'),'Поиск по недоступному назначению');
        find('Папка');check($('command-results').hidden && rows('shell-commands')===0,'Скрыта таблица без подходящих команд');
        find('прежняя-папка');check(rows('devices')===1 && rows('shell-commands')===1 && rows('files')===0 &&
              rows('transfers')===0 && Number.isFinite(sessions.get(selectedSession).recent),'Сеанс состоит только из команды без подтверждения');
        $('from').value='2031-01-01';filterReport();check(rows('devices')===0 && $('outgoing').hidden,'Ограничение команд по датам');
    }else if(document.title==='История'){
        check(selectedSession==='empty-16' && rows('transfers')===0 && rows('files')===0,'Пустое последнее подключение');
        const jump=$('empty-transfers').querySelector('button');
        check(jump && jump.textContent.includes('Открыть подключение'),'Переход из пустого подключения');
        jump.click();
        check(selectedSession==='prior' && page.session===1 && rows('files')===1 && rows('transfers')===0,'Переход к прошлой записи на другой странице');
        check($('empty-transfers').textContent.includes('Исходный путь установить не удалось') &&
            $('files').textContent.includes('перезапись.txt'),'Пояснение к реальной записи без исходного пути');
        $('from').value='2026-11-25';filterReport();
        check(!$('empty-transfers').querySelector('button'),'Переход учитывает период');
        $('reset').click();find('перезапись.txt');
        check(selectedSession==='prior' && rows('files')===1 && rows('transfers')===0,'Поиск находит историческую запись без ложного переноса');
    }else{
        check(rows('sessions')===2 && rows('transfers')===10,'Два направления передачи и дедупликация');
        const ops=[...$('files').tBodies[0].rows];
        check(ops.length===8,'Группировка записи с USB-уведомлениями и повторное создание');
        const removed=ops.find(row=>row.textContent.includes('Удалено с носителя'));
        check(removed && removed.cells[1].textContent==='—' && removed.cells[4].textContent==='—','Отдельное удаление без вымышленного автора');
        const created=ops.find(row=>row.textContent.includes('Копирование на USB из каталога') && row.textContent.includes('Windows Security'));
        check(created && created.textContent.includes('writer.exe') && created.textContent.includes('C:\\Работа\\Сметы') &&
            created.cells[3].textContent.includes('E:\\документ.txt'),'Исходная папка в строке создания по ID записи Windows');
        const probable=ops.find(row=>row.textContent.includes('Вероятное копирование на USB') && row.textContent.includes('C:\\План'));
        check(probable && probable.textContent.includes('C:\\План') && !probable.textContent.includes('SHA-256'),'Запись без хеша помечена вероятной');
        check(ops.filter(row=>row.textContent.includes('C:\\Черновики')).length===1,'Повторное создание с другим источником по UID');
        find('etw-папка');check(rows('files')===2 && rows('transfers')===2,'Результат ETW в истории со связанным уведомлением и без него');
        check($('transfers').textContent.includes('ядра Windows (ETW)') && $('transfers').textContent.includes('PID 250'),
            'Основание ETW и ID процесса');
        check($('transfers').textContent.includes('Чтение — ETW, запись — Windows Security 4663'),
            'Смешанная пара не приписывает запись ядру');
        find('сметы');check(rows('files')===1 && rows('transfers')===1,'Поиск исходного каталога');
        const inbound=$('transfers').tBodies[0].rows[0];
        check(inbound.cells[0].textContent.includes('Компьютер → USB') &&
            inbound.cells[1].textContent==='C:\\Работа\\Сметы\\документ.txt' && inbound.cells[2].textContent==='E:\\документ.txt',
            'Направление и полные пути копирования на USB');
        find('замена.txt');
        check($('transfers').textContent.includes('Изменение существующего файла'),'Перезапись по уведомлению тома');
        find('черновики');
        check($('transfers').textContent.includes('Только чтение на компьютере') && !/чтение с носителя/i.test($('transfers').textContent),
            'Уведомление на флешке не устанавливает автора записи');
        find('имя-до.txt');
        check(rows('files')===1 && $('files').textContent.includes('имя-после.txt'),'Поиск по прежнему имени');
        find('');
        check(rows('archives')===20 && $('archive-pages').querySelectorAll('button').length===2,'Пагинация действий');
        $('archive-pages').querySelectorAll('button')[1].click();
        check(rows('archives')===1,'Вторая страница действий');
        check($('transfers').textContent.includes('Содержимое совпало') && $('transfers').textContent.includes('Вероятный перенос'),'Разные основания');
        check([...$('transfers').querySelectorAll('details')].some(d=>d.textContent.includes('a'.repeat(64))),'Отображение SHA-256');
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
    if scope == "history":
        template = template.replace("<title>Журнал USB</title>", "<title>История</title>")
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
    def notification(change, second, **fields):
        return dict(current, type="file", source="volumeWatcher", change=change,
                    path=r"E:\документ.txt", time=f"2026-11-24T08:01:{second:02}Z", **fields)
    file_changes = [
        notification("created", 0), notification("changed", 0),
        dict(current, type="file", accessMask="0x2", path=r"E:\документ.txt",
             account="writer", process="writer.exe", logEpoch="sample", recordId=101, time="2026-11-24T08:01:00Z"),
        notification("deleted", 3), notification("created", 4, uid="recreated"),
        dict(notification("renamed", 10), path=r"E:\имя-после.txt", oldPath=r"E:\имя-до.txt"),
        dict(current, type="file", accessMask="0x2", path=r"E:\задачи\документ.txt", account="b", process="b.exe",
             logEpoch="sample", recordId=201, time="2026-11-24T08:01:10Z"),
        dict(notification("created", 14), path=r"\Device\HarddiskVolume55\реестр.txt"),
    ]
    inbound = dict(current, type="transfer", direction="toUsb", sourceRecordId=98, destinationRecordId=101,
                   logEpoch="sample", localPath=r"C:\Работа\Сметы\документ.txt", path=r"E:\документ.txt",
                   destination=r"E:\документ.txt", evidence="matchingContent", sha256="c"*64, time="2026-11-24T08:01:00Z")
    recreated = dict(current, type="transfer", direction="toUsb", destinationEventUid="recreated", sourceRecordId=111,
                     localPath=r"C:\Черновики\документ.txt", path=r"E:\документ.txt", destination=r"E:\документ.txt",
                     evidence="observedMatchingContent", destinationChange="Created", sha256="d"*64, time="2026-11-24T08:01:04Z")
    overwrite_notice = dict(notification("changed", 18), path=r"E:\замена.txt", uid="changed-demo")
    overwrite = dict(recreated, time=overwrite_notice["time"], destination=overwrite_notice["path"],
                     path=overwrite_notice["path"], localPath=r"D:\Проекты\замена.txt", sourceRecordId=115,
                     destinationEventUid=overwrite_notice["uid"], destinationChange="Changed")
    probable = dict(inbound, localPath=r"C:\План\документ.txt", destination=r"E:\задачи\документ.txt",
                    path=r"E:\задачи\документ.txt", sourceRecordId=199, destinationRecordId=201, evidence="pairedAccess",
                    sha256=None, time="2026-11-24T08:01:10Z")
    kernel = dict(current,type="transfer",direction="toUsb",localPath=r"C:\ETW-папка\реестр.txt",
                  path=r"E:\реестр.txt",destination=r"E:\реестр.txt",usbNtPath=r"\Device\HarddiskVolume55\реестр.txt",
                  time="2026-11-24T08:01:14Z",evidence="kernelMatchingContent",sha256="e"*64,processId=250)
    kernel_only = dict(kernel,localPath=r"C:\ETW-папка\отдельно.txt",path=r"E:\отдельно.txt",destination=r"E:\отдельно.txt",
                       usbNtPath=r"\Device\HarddiskVolume55\отдельно.txt",time="2026-11-24T08:01:15Z",evidence="pairedKernelAccess",
                       source="kernelReadSecurityWrite",destinationRecordId=240,logEpoch="sample",sha256=None)
    usb_write = dict(current, type="file", time=kernel_only["time"], path=kernel_only["usbNtPath"],
                     accessMask="0x2", logEpoch="sample", recordId=240, processId=250, process="writer.exe", account="writer")
    with tempfile.TemporaryDirectory(prefix="usb-audit-viewer-") as temp:
        browser, folder = local_browser(), Path(temp)
        render(browser, folder, [archive], "archive")
        shell_copy = dict(current, type="transfer", direction="toUsb", source="shellFileOperation",
                          evidence="shellDestinationObserved", operation="copy", shellEventId=18905, processId=321,
                          localPath=r"C:\Папка\ноль.txt", path=r"H:\ноль.txt", destination=r"H:\ноль.txt",
                          sourcePath=r"C:\Папка\ноль.txt", destinationEventUid="usb-write")
        shell_move = dict(shell_copy, direction="fromUsb", operation="move", sourcePath=r"H:\ноль.txt",
                          destination=r"D:\Приём\ноль.txt", localPath=r"D:\Приём\ноль.txt", destinationChange="ChangeTime")
        del shell_move["destinationEventUid"]
        command = dict(shell_move,type="shellCommand",evidence="shellOutcomeUnknown",sourcePath=r"H:\частный.txt",
                       path=r"H:\частный.txt",destination=r"C:\Private\частный.txt",localPath=r"C:\Private\частный.txt",
                       uid="unknown-command")
        command.pop("destinationChange")
        older_command = dict(command, session="orphan", uid="orphan-command", time="2026-11-23T08:10:00Z",
                             destination=r"C:\прежняя-папка\частный.txt",localPath=r"C:\прежняя-папка\частный.txt")
        # Закрытый архив с началом сеанса удалён. Файловые записи сохранили сеанс и устройство.
        render(browser, folder, [dict(notification("changed", 0), path=r"H:\ноль.txt", uid="usb-write"),
                                 shell_copy, shell_move,command,dict(command),older_command], "shell")
        prior = dict(current, session="prior")
        write = dict(prior, type="file", accessMask="0x2", path=r"E:\перезапись.txt")
        empty = [dict(current, session=f"empty-{i}", time=f"2026-11-25T08:{i:02}:00Z") for i in range(17)]
        unrelated = dict(current, deviceId="OTHER", session="other", time="2026-11-25T08:14:30Z")
        render(browser, folder, [prior, write, dict(prior, type="disconnect", time="2026-11-24T09:00:00Z"),
                                 unrelated, dict(unrelated, type="file", path=r"G:\чужой.txt", accessMask="0x2"),
                                 dict(unrelated, type="disconnect", time="2026-11-25T08:15:00Z"), *empty], "history")
        render(browser, folder, [legacy, read, current, transfer, other, dict(transfer), observed, dict(observed), possible,
                                 archive, dict(archive), *archive_more, *file_changes, inbound, dict(inbound), recreated, probable,
                                 kernel, kernel_only, usb_write, overwrite_notice, overwrite], "all")
    print("Пройдены проверки отчёта для двух версий записей, фильтров, пагинации и отдельного архива.")


if __name__ == "__main__":
    main()
