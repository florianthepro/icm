# Setup

1. [https://account.apple.com/account/manage](https://account.apple.com/account/manage)
2. Anwendungsspezifische Passwörter
3. Neues Passwort erstellen:
   - Name: `icm`
4. Passwort kopieren
5. [https://icm.ftpsmt.com/](https://icm.ftpsmt.com/)
6. Mit iCloud-Adresse und App-Passwort anmelden

# Ablauf

1. Alle E-Mails aus Unterordnern in den Hauptordner verschieben
2. Alle Ordner löschen
3. Alle Regeln löschen
4. Benötigte Ordner erstellen

Webseite macht: E-Mails sortieren:
   - API<!--(Claude)--> erhält Absender- und Empfängeradresse
   - API<!--(Claude)--> gibt Ordnernamen zurück
   - Antwort validieren
   - E-Mail in den Ordner verschieben
```
goto https://account.apple.com/account/manage
>Anwendungsspezifische Passwörter<
name: icm
<copy it>
goto https://icm.ftpsmt.com/
enter icloud mail and app password



website will:
1. move every subfolder mail to main folder
2. delete all folders and rules
3. create needet folders
4. sort mails
  1. api(claude agent will get source and destionation mail adresse and will response with the foldername site will validatet it then sort
```
<!--zjgrszpijgxlmkgzwoefawkjfh-->
