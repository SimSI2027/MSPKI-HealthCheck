# Testing the tool on a real domain (the first live run)

This page is for the person who runs the tool for the first time on a real, domain-joined Windows computer.
You do not need to be a PKI or PowerShell expert. The tool only **reads**. It does not change Active Directory,
a certificate authority (CA), the registry or any server. The only thing it writes is a folder of result files
on this computer.

The purpose of this first run is to learn two things: what your PKI looks like, and whether the tool itself
behaves on a real system. The tool has never run against a real AD CS before, so the log it writes is
as important as the results.

## Before you start

- Use a Windows computer that is **joined to the domain**, and log on with a normal domain account.
- Use **Windows PowerShell 5.1** (the blue window called "Windows PowerShell"). Do not use "PowerShell 7".
- Copy the project folder to the computer. Nothing has to be installed and no internet access is needed.
- **Tell your security team first.** The tool asks Active Directory and the CAs a lot of questions in a short
  time (templates, CA properties, the CA database, web addresses found in certificates). Monitoring tools may
  treat that as reconnaissance and raise an alert. A heads-up avoids a false alarm.
- If you downloaded the folder as a zip file, Windows may block the scripts. Open Windows PowerShell in the
  project folder and run `Get-ChildItem -Recurse | Unblock-File` once. If Windows still says that running scripts
  is disabled, ask your administrator. Please do not turn the execution policy off to get past this.

## Step 1: run it as a normal user

1. Open **Windows PowerShell** the usual way (not "Run as administrator").
2. Go to the project folder, for example: `cd C:\Tools\MSPKI-HealthCheck`
3. Start the tool: `.\Invoke-MspkiHealthCheck.ps1`
4. Wait. A full run can take several minutes on a big PKI, because every web address is tried with a time limit.
   If nothing seems to happen for more than five minutes, press **Ctrl+C**. The tool still writes what it has
   found so far.
5. When it finishes it prints a short list of results that need attention, the folder it wrote to, and an
   **exit code**. To see the exit code again, type `$LASTEXITCODE`.

Everything is written to a new folder named like `out\20261121-093015\` (year, month, day, hour, minute, second).
It contains four files:

| File | What it is |
|---|---|
| `report.html` | The report. Double-click it to open it in a browser. It works offline. |
| `findings.csv` | The same results as a table that opens in Excel. |
| `results.json` | Every result with its evidence, plus how the run went. **Send this file back.** |
| `run.log` | A step-by-step diary of the run with times. **Send this file back.** |

## Step 2: run it again as an administrator

Some checks need more rights than a normal user has (for example reading the list of certificates a CA has
issued). A normal user gets "permission denied" for those. That is expected and is not a fault.

1. Close the window. Open **Windows PowerShell** with **Run as administrator**, using an account that has
   read rights on the CAs if you have one.
2. Run the same command again: `.\Invoke-MspkiHealthCheck.ps1`

This writes a second folder. Keep both, so the two runs can be compared. Note which folder is which.

## What a good result looks like

"Good" here does not mean "no problems found". A real PKI usually has a few things worth a look. It means the
**tool worked properly**:

- It finished and printed `Exit code: ...` and the paths of the four files. It did not stop with a red error message.
- The list of Certification Authorities is the one you expect. Each CA you can reach has a result that says
  "CA properties read" and, in its details, a line `Connection string that answered`.
- Nothing is marked **Error**, and no result has the code `INTERNAL_ERROR`. That code means the tool itself hit
  something it did not expect. That is the most useful thing you can send back.
- `run.log` ends with lines like `Wrote ...results.json` and `Run finished: completed True`.
- Results are marked honestly. A result that is only a guess says **Inferred** or **Referenced**, not **Confirmed**.

The exit code is a quick summary:

| Exit code | Meaning |
|---|---|
| 0 | Everything passed or did not apply. |
| 2 | Some information worth a look, no warnings. |
| 3 | At least one warning. |
| 4 | At least one failure, for example an expired certificate or a web address that does not answer. |
| 5 | The run is incomplete because something is not supported on this computer, a check hit an error, or you stopped it. |
| 6 | The run is incomplete because the account lacks permission for some checks. Expected for a normal user. |

On a first run, 3 or 4 is quite possible and not a sign that the tool is broken. 5 deserves a look at `run.log`.

Things that are **not** good, and that you should mention when you send the files back:

- The tool stops with an error message.
- The log shows a line `Stage ... started` with no later `Stage ... took ...` line. That is where it got stuck.
- A result that you know is wrong, such as a CA that is listed as unreachable but is up, or a certificate
  reported as expired that is not.
- Anything that looks like a **Fail** on a web address that other computers reach fine.

## What the log tells us

`run.log` is meant to be read by someone who was not there. For each CA it records every connection string that
was tried, every property that was asked for (with the type of answer and how long it took) and the time each
stage took. It never records certificate contents, keys or passwords. It does record names (see the warning
below), so please read that part before you send anything.

## What to send back

Send these two files from each run folder (normal user and administrator):

1. `results.json`
2. `run.log`

**Warning: these files contain real names.** They hold the names of your servers, domains, CAs, templates,
accounts and web addresses. Treat them like any other internal document.

- **Never commit them to git.** The project folder is public on the internet. Do not add them to the project.
- **Never post them publicly:** no issue tracker, no public chat, no forum.
- Send them only through a private channel to the person who asked for them. Putting them in a zip file first is fine.
- `report.html` and `findings.csv` contain the same names, so the same rule applies if you share them.

The output folder `out\` is excluded from git on purpose. If you copy result files somewhere inside the project
folder, check that they are not staged before you commit anything.

## Using the window (GUI) instead of the command line

The same check is available as a window. Start it like this, from a normal (not elevated) Windows PowerShell 5.1 prompt in the
project folder:

```powershell
.\Start-MspkiHealthCheckGui.ps1
```

(If it says it needs a single-threaded session, use `powershell.exe -STA -File .\Start-MspkiHealthCheckGui.ps1`.)

It does exactly what the command-line tool does and writes the same files to a new `out\<date-time>\` folder. These are the
things worth trying, and what you should see:

1. **A full run.** Before the first run the Summary tab shows a welcome page. Press **Run** (or F5). The Run button greys out
   and Cancel turns on. The thin progress bar moves, the status bar at the bottom names the current step and the address being
   checked, and the **Run Log** tab fills with lines (warnings amber, errors red, each with a level word). The window never
   freezes: you can switch tabs and move it while the run is going. When it finishes, the **Summary** tab opens with a health
   banner (green, amber or red, with a sentence), four tiles (CAs, CA certificates, endpoints, templates), a tile per status and
   per severity (select one to jump to those findings), one card per CA, the top issues (select one to open it) and the
   discovery coverage with the reason for every method that failed. "Open report" turns on. Check **Findings** (search box,
   status chips, the Severity / Category / Confidence lists, "Group by category", click a column heading to sort, right-click a
   row to copy, "Export filtered view" writes a CSV into the run folder), and the **Discovery Map** (icons, confidence badges,
   Expand all / Collapse all, details on the right).
2. **Cancel.** Press **Run** again and, after a few seconds, press **Cancel**. The text says it is cancelling, and within a few
   seconds the run stops. A yellow note on the Summary tab says the results are partial, and the files were still saved.
3. **Closing during a run.** Press **Run** and close the window with the X while it runs. The window stays for a few seconds
   saying it is cancelling, then closes by itself. The newest folder under `out\` has a `results.json` whose `RunInfo.Completed`
   is `false`.
4. **Opening an earlier run.** Press **Open results** (Ctrl+O), choose a `results.json` from an earlier run. Nothing is scanned;
   the Summary, Findings, Map and Run Log tabs show that run, with a note saying so.
5. **A wrong file.** Choose a file that is not a results file. A message says what is wrong and the window stays as it was.

If something looks wrong, tell us which of the five it was and what you saw, and send `run.log` from that run (see "What to
send back"). Please do not send screenshots or the result files: they contain real names.

## What the tool does and does not do

- It only reads. It does not enroll, request, revoke, publish, restart or change anything.
- It only contacts addresses it found in Active Directory, in the CAs, in certificates and CRLs, or in local
  policy. It does not scan your network.
- Web checks are plain anonymous requests. They do not send your credentials and do not use a proxy.
- It does not send the anonymous request to the NDES admin page by default, because on a wrongly configured
  server that request can cause the server to create a challenge password.
- It does not contact directory servers outside your forest, even if a certificate names one.

Two switches are off by default and should stay off for the first test:
`-UseSystemProxy` (let the web checks use the system proxy) and `-IncludeNdesAdminProbe` (send the one anonymous
request to the NDES admin page).

## If something goes wrong

| What you see | What to do |
|---|---|
| "Running scripts is disabled on this system" | Ask your administrator. Do not turn the execution policy off. |
| "This computer is not joined to a domain" | Run it on a domain-joined computer. |
| It is very slow | Wait, or run `.\Invoke-MspkiHealthCheck.ps1 -TimeoutSeconds 10` if the network is slow. Ctrl+C stops it and keeps what it found. |
| You only want to see that it starts | Run `.\Invoke-MspkiHealthCheck.ps1 -SkipNetwork`. It then reads Active Directory only and contacts no other server. |
| Many "permission denied" results | Normal for a normal user. Run step 2 as an administrator. |
