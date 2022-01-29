# seb-keys-extractor

Generate X-SafeExamBrowser-ConfigKeyHash header:
```
python3 main.py config "http://localhost:8000/index.php" SebClientSettings.seb ""
```

Generate BrowserExamKey:
```
python3 main.py browser SafeExamBrowser.exe SebClientSettings.seb ""
```

Generate X-SafeExamBrowser-RequestHash header:
```
python3 main.py request "http://localhost:8000/index.php" SafeExamBrowser.exe SebClientSettings.seb ""
```
