# Friction Log: Sentinel MCP (Build, Ship, Shape: Amazon Developer Hackathon)

Builder: Simanyana (Soweto, South Africa). First-time builder, Windows laptop, unstable home connection.
Scope: setup through two working MCP tools, a token lock and an AI briefing on Amazon Bedrock (6 to 15 Oct 2026). Updated 15 Oct 2026.
Each entry: task, steps, expected vs actual, severity, workaround, suggestion.

## Summary

| # | Tool | Issue | Severity |
|---|------|-------|----------|
| 1 | AWS IAM console | Unclear starting point for "admin user instead of root" | Low |
| 2 | MCP Python SDK v2 | FastMCP renamed to MCPServer | Medium |
| 3 | Documentation / copy-paste | Python double underscores lost when copying code | Medium |
| 4 | MCP Inspector (npx) | Download fails on unstable connection; confirm prompt | Low |
| 5 | npm CLI | Multi-line paste split a config command | Low |
| 6 | Lambda Function URL | Auth NONE alone does not make the URL public | Medium |
| 7 | AWS CloudShell | CLI pager hides command output | Medium |
| 8 | Lambda create-function | Generic error for an empty variable | Low |
| 9 | Lambda zip from Windows | Exec bit and LF line endings required | Medium |
| 10 | GuardDuty API | Sample findings not marked as samples | Low |
| 11 | AWS CloudShell | New session loses variables and the pager setting | Medium |
| 12 | Lambda configuration | Updating one environment variable replaces all of them | Medium |
| 13 | Amazon Bedrock | First model call blocked while the account is being verified | Medium |
| 14 | Amazon Bedrock | Newest model listed in the catalog but not available for the account | Medium |
| 15 | Bedrock / Service Quotas | Quota applied as 0 shows up as a daily-token throttling error | High |
| 16 | Lambda zip layout | Dependencies nested under a folder; function returns HTTP 502 with no reason | High |
| 17 | AWS CloudShell upload | Upload banner reports success but the file is not in the home folder | Medium |

Onboarding: zero to a working local MCP server took about one session. Zero to a public Lambda URL took about one more, mostly spent on packaging and permissions. Adding two real AWS-backed tools (CloudTrail sign-ins, GuardDuty findings) and a token lock took a third. Getting a first successful Amazon Bedrock call took about two further days because of account verification and a zero quota.

---

## 1. AWS IAM console: where to start for an admin user
- **Task:** set up a safe AWS account (MFA, admin user instead of root, budget alert)
- **Steps:** searched for IAM, landed on the "Create user group" screen
- **Expected:** a clear path to "create an admin user"
- **Actual:** unsure whether a user group was the right first step; the console shows groups, users and Identity Center as separate entry points
- **Severity:** Low
- **Workaround:** asked for step-by-step confirmation, then created the group and user
- **Suggestion:** add a "Create your first admin user" guided flow on the IAM dashboard for new accounts

## 2. MCP Python SDK v2: FastMCP renamed to MCPServer
- **Task:** write a minimal MCP server in Python
- **Steps:** installed mcp 2.x and used the commonly documented FastMCP import
- **Expected:** the usual import works
- **Actual:** import failed; the class is now `MCPServer` in `mcp.server.mcpserver`
- **Severity:** Medium
- **Workaround:** changed the import
- **Suggestion:** keep a deprecation alias for FastMCP and link a v1-to-v2 migration note from the README

## 3. Documentation and copy-paste: double underscores lost
- **Task:** run the server file locally
- **Steps:** copied the `if __name__ == "__main__":` guard from rendered text
- **Expected:** identical code after paste
- **Actual:** the double underscores were stripped, giving a NameError for `_name_`
- **Severity:** Medium (a beginner cannot tell why it fails)
- **Workaround:** removed the guard and ran the app through uvicorn directly
- **Suggestion:** docs should prefer a launch command (`uvicorn app:app`) over `__main__` guards in beginner examples, so no dunder names are needed

## 4. MCP Inspector: download failure and confirm prompt
- **Task:** test the local MCP server with MCP Inspector
- **Steps:** ran `npx @modelcontextprotocol/inspector` on an unstable connection
- **Expected:** Inspector starts
- **Actual:** npx asks "Ok to proceed? (y)", then the download failed repeatedly with ECONNRESET
- **Severity:** Low
- **Workaround:** raised npm fetch retries and retry timeout, then retried
- **Suggestion:** mention the retry settings in the Inspector quick start, and note the first-run confirm prompt

## 5. npm CLI: multi-line paste breaks config commands
- **Task:** set npm retry options
- **Steps:** pasted two config commands; the terminal wrapped one across two lines
- **Expected:** both commands run
- **Actual:** the split command failed with a confusing error
- **Severity:** Low
- **Workaround:** typed each command as one line
- **Suggestion:** docs should show one command per code block

## 6. Lambda Function URL: auth NONE is not enough to be public
- **Task:** give the Lambda a public HTTPS URL
- **Steps:** `create-function-url-config` with auth-type NONE
- **Expected:** the URL is public after one command
- **Actual:** two further resource-policy permissions are needed (InvokeFunctionUrl, then InvokeFunction via function URL)
- **Severity:** Medium
- **Workaround:** ran two `add-permission` commands
- **Suggestion:** have `create-function-url-config` with NONE add both statements, or print a warning that the URL is not yet public

## 7. AWS CloudShell: pager hides command output
- **Task:** read the result of `create-function-url-config`
- **Steps:** pasted the command into CloudShell
- **Expected:** JSON output appears
- **Actual:** the screen showed old output and looked frozen; the CLI pager was holding the display
- **Severity:** Medium (a beginner assumes the command failed)
- **Workaround:** `export AWS_PAGER=""`
- **Suggestion:** disable the pager by default in CloudShell

## 8. Lambda create-function: unhelpful error for an empty variable
- **Task:** create the function with a role ARN built from an account-ID variable
- **Steps:** ran `create-function` after the variable was accidentally empty
- **Expected:** an error pointing to the empty account ID
- **Actual:** a generic ValidationException about the role ARN pattern
- **Severity:** Low
- **Workaround:** printed the variable and re-ran with the ARN written out
- **Suggestion:** echo the offending value in the error message

## 9. Windows to Lambda zip: exec bit and line endings
- **Task:** package `run.sh` and dependencies for Lambda from a Windows laptop
- **Steps:** planned to zip locally
- **Expected:** a zip built on any OS works
- **Actual:** `run.sh` needs the executable bit and LF line endings, which Windows zips lose
- **Severity:** Medium
- **Workaround:** built the zip in AWS CloudShell (Linux)
- **Suggestion:** document the Linux build step prominently for Windows users, or offer a beginner path that avoids shell-script handlers

## 10. GuardDuty sample findings are not marked as samples in the API
- **Task:** show GuardDuty sample findings in an app and label them honestly as demo data
- **Steps:** create-sample-findings, then get-findings through the API
- **Expected:** a field or title marker saying the finding is a sample
- **Actual:** no "[SAMPLE]" in the title; findings look like real attacks (the fake account 111122223333 appears only inside the description text)
- **Severity:** Low
- **Workaround:** match the fake account number in the description
- **Suggestion:** add an explicit `sample: true` field to the finding

## 11. AWS CloudShell: a new session loses variables and the pager setting
- **Task:** keep testing the deployed MCP server across several sessions
- **Steps:** opened CloudShell again (new tab, and after a restart), re-ran earlier commands
- **Expected:** the shell setup carries over
- **Actual:** `URL`, `TOKEN` and `AWS_PAGER` were gone; commands that depend on them returned nothing or an unauthorized error, and the cause was not visible
- **Severity:** Medium (a beginner cannot tell an empty variable from a server problem)
- **Workaround:** reload the variables from AWS (`get-function-url-config`, `get-function-configuration`) at the start of every session
- **Suggestion:** let CloudShell persist a user-defined profile with common settings such as AWS_PAGER, or warn when a variable used in a command is empty

## 12. Lambda update-function-configuration replaces all environment variables
- **Task:** add one secret (MCP_TOKEN) to an existing function
- **Steps:** update-function-configuration with --environment
- **Expected:** the new variable is added next to the existing ones
- **Actual:** the whole set is replaced, so every existing variable must be repeated or it is deleted (here AWS_LWA_PORT and AWS_LAMBDA_EXEC_WRAPPER, without which the function stops working)
- **Severity:** Medium
- **Workaround:** repeated all variables in the command
- **Suggestion:** offer a merge option, or print a warning listing the variables that will be removed

## Addendum to #5: unclosed quote in a pasted command
A long pasted command with a missing closing quote left CloudShell on a `>` continuation prompt with no message explaining it, and Ctrl+C did not respond until the terminal had focus. Suggestion: show a hint such as "unfinished quote, press Ctrl+C to cancel" on continuation prompts.

## 13. Amazon Bedrock: first model call blocked while the account is being verified
- **Task:** call a Claude model from the CLI to confirm Bedrock access
- **Steps:** submitted the one-time Anthropic use-case form, then ran a Converse call
- **Expected:** a working reply once the form was submitted
- **Actual:** AccessDeniedException saying the account is being verified for up to 2 hours; the console gave no indication of this status beforehand
- **Severity:** Medium
- **Workaround:** built a rule-based fallback into the briefing tool and retried later
- **Suggestion:** show account verification status in the Bedrock console before the first call

## 14. Amazon Bedrock: newest model listed but "not available for this account"
- **Task:** use the newest Claude Haiku model for plain-English briefings
- **Steps:** found the model in the console catalog and in list-inference-profiles, then called it
- **Expected:** a model shown in the catalog can be called
- **Actual:** AccessDeniedException "is not available for this account", with a suggestion to contact AWS Sales
- **Severity:** Medium
- **Workaround:** used Claude Haiku 4.5 through the global inference profile instead
- **Suggestion:** mark models that are not enabled for the account in the catalog

## 15. Bedrock and Service Quotas: a quota of 0 appears as a "too many tokens per day" error
- **Task:** make a 20-token test request to Claude Haiku 4.5 and to Amazon Nova Lite
- **Steps:** ran Converse calls on a new account
- **Expected:** a small request succeeds
- **Actual:** ThrottlingException "Too many tokens per day" on every on-demand model, even for one tiny request; the real cause was visible only in Service Quotas, where the applied value for the model's cross-region quotas was 0 against a default of 10,000 requests and 5,000,000 tokens per minute (some quotas not adjustable, e.g. for Nova)
- **Severity:** High (blocked the AI feature for about two days)
- **Workaround:** requested an increase through Service Quotas, which went to an AWS Support case; after it closed the model worked
- **Suggestion:** state "your quota is 0" in the error text and show per-model quota in the Bedrock console

## Addendum to #3: the same dunder problem hit twice more
Code containing double underscores (a `__name__` in a fallback message, and again in a patch command) lost the underscores when copied, producing an AttributeError and an AssertionError. Suggestion: avoid dunder names in beginner examples or provide a downloadable file.

Addendum (15 Oct): a grep pattern copied from the chat lost its double underscores, so it matched nothing. The check looked like a failure, but the file was fine. Suggestion: use a pattern that avoids double underscores, or count matches with grep -c.

## 16. Lambda zip layout: dependencies nested under a folder (15 Oct)
- **Task:** deploy the updated MCP server code with its dependencies
- **Steps:** zipped the package folder as a directory, then uploaded the zip with update-function-code
- **Expected:** the function starts and answers through its Function URL
- **Actual:** HTTP 502 with the body "Internal Server Error." The Lambda log showed "No module named uvicorn," because every file was stored under a package/ prefix instead of the top level of the zip
- **Severity:** High (the endpoint was unavailable for about 20 minutes)
- **Workaround:** built the zip from a staging folder so dependencies sit at the top level, then checked the layout with unzip -Zl before deploying
- **Suggestion:** provide a build script in the documentation; the Function URL should return a reason for a startup failure, not a generic 502

## 17. AWS CloudShell upload reports success but the file is missing (15 Oct)
- **Task:** upload the corrected app.py to the deployment folder
- **Steps:** Actions → Upload file, then mv from the home folder
- **Expected:** the file appears in the home folder after the success banner
- **Actual:** the banner named /home/cloudshell-user, but mv reported "No such file or directory." A second upload appeared correctly
- **Severity:** Medium
- **Workaround:** re-uploaded and checked with ls before running mv
- **Suggestion:** show the saved path and refresh the file list only after the upload has finished

## Addendum to #11: variables lost after a session reset (15 Oct)
The URL and TOKEN variables were empty after the session reset. curl then printed "option : blank argument where content is expected," which does not name the variable. Reloading the variables from AWS fixed it.
