# "Assistenza Clienti" — Android surveillance app impersonating Italian carrier support

`com.itassistenzaclienti`, published under the developer name "Telecomunicazione Mobile",
is an Android application that presents itself as customer support for an Italian mobile
carrier. It is a thin WebView shell driven in real time by its operator's server.

Analysed on 2026-09-03 on a dedicated test device (Lenovo TB128XU, Android 13) by
Riccardo Bacci (Mythos Sentinel), Terni, Italy. The C2 was re-verified as **live on 2026-09-05**.

## What the app actually is

The app does not carry its own user interface: on launch it loads
`https://telecomunicazioni-mobile.com/support/9.html?language=it&packagename=com.itassistenzaclienti`
and renders whatever the operator serves. The HTML shown at analysis time asks the victim
for a "unique ID to give the operator" and offers an "Invia File" (send file) button.

The decisive part is a native JavaScript bridge named `mysupport`, registered with
`addJavascriptInterface`, which exposes **three methods to the remote HTML**:

| method | effect |
|---|---|
| `getToken()` | returns the pairing ID |
| `openVoiceNotesActivity()` | starts an internal activity holding an `android.media.AudioRecord` field and a method returning a `java.io.File` — **microphone recording to file** |
| `pickFile(String)` | opens a file chooser — **exfiltration of a device file** |

Because the HTML is served by the operator, the set of actions actually triggered can be
changed at any time without updating the app. The capabilities above are in the app's own
bytecode and are therefore independent of what the server chooses to serve on a given day.

Supporting observations:

- Requested permissions: microphone, `MANAGE_OWN_CALLS`, package installation.
  No camera, SMS, contacts, location or storage permissions.
- `FLAG_SECURE` is set: the app's own screens cannot be screenshotted by the user.
- Strings (including `mysupport`, URLs and intent actions) are encrypted and decoded at
  runtime; the bytecode contains opaque predicates. 
- The activity registers `onCallReceived(...)` and `onUrlReceived(...)` handlers, so the
  server can push "call" and "url" events.
- The recorder activity is not exported and opens a UI with record/send buttons: it needs a
  tap, i.e. the operator has to talk the victim through it.
- `MediaProjection`, `WebSocket` and `MultipartBody` symbols present in the dex come from a
  bundled Stream video SDK and Retrofit; their presence alone is **not** evidence of use and
  is not claimed here.

The exfiltrated payload was **not** captured. Doing so would have required impersonating the
operator and actually operating the surveillance tooling. What is documented here is
capability and observed behaviour.

## How the indicators were obtained

TLS to the C2 was decrypted by appending an analysis CA to the `bundle.pem` shipped in the
app's own `res/raw/` (the app trusts that bundle via `network_security.xml`; there is no
application-level pinning), then repackaging and re-signing the base APK and its three
splits for installation on the test device. The traffic listed above is decrypted,
real traffic, not inferred from static analysis.

## Signing certificate

The original sample is signed with a certificate whose Distinguished Name is `CN=teleit`,
with **no organisation and no country field**, SHA-256:

```
c37ab648 96d44ffe 831f6309 e5f66541 3f47b42f 6341d1ef a81b23ba 5d6545ad
```

This is recorded for correlation only; it is not part of the indicator files, since MVT does
not match on signing certificates.

## Relationship to Spyrtacus — open, not asserted

The lure ("Italian mobile carrier support") resembles the `2026-04-09_sio_spyrtacus`
collection, whose delivery domain is `supporto-mobile.it`. We found **no technical link**:

- the C2 IP `93.186.254.171` does not appear in that collection, and does not share a network
  with `5.56.12.150` / `89.46.67.218`;
- our C2 serves **no favicon** (HTTP 404), so the Spyrtacus favicon hash does not apply;
- the architecture differs: this sample is a remote-driven WebView with a three-method
  native bridge, not a native implant with screenshotting, call recording and WhatsApp export.

We report it as a distinct collection. If maintainers have visibility we lack, merging it
into the Spyrtacus collection is theirs to decide.

## C2 status

Verified on 2026-09-05: `telecomunicazioni-mobile.com` resolves to `93.186.254.171`
(reverse: `host171-254-186-93.serverdedicati.aruba.it`, a dedicated server at Aruba, Italy),
HTTPS certificate issued by Let's Encrypt on 2026-07-21, and
`/support/9.html?language=it&packagename=com.itassistenzaclienti` still returns HTTP 200
with the same "unique ID" panel calling `mysupport.getToken()`. The infrastructure is
actively maintained.

## Sources

- Riccardo Bacci (Mythos Sentinel), technical analysis of the sample and decrypted C2
  traffic, 2026-08-31 / 2026-09-03: https://mythossentinel.com/en/assistenza-clienti-android-surveillance-app

## Files

- **it_assistenza_clienti.stix2**: STIX2 indicators for use with MVT
- **domains.txt**: C2 domain
- **ip-addresses.txt**: C2 IP
- **package_names.txt**: Android package name
