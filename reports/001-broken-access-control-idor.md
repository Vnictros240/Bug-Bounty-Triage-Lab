# 001 - Broken Access Control: IDOR in /api/users/{id}

**Repository:** `Bug Bounty Triage Simulation Lab`
**Creator:** `Victor Sullivan`
**Mentor:** `Senior Bug Bounty Triage Engineer`
**Analyst:** `Junior Triage Analyst`

---

## 🧾 Summary
A security researcher submitted a report claiming that an **Insecure Direct Object Reference (IDOR)** vulnerability exists on the `/api/v1/users/{id}` endpoint.

According to the report, any authenticated user can retrieve the full profile details of *any other user* by simply manipulating the `id` parameter in the API request. The leaked data allegedly includes sensitive Personally Identifiable Information (PII) such as full name, email address, phone number, and home address.

This vulnerability falls under **OWASP Top 10: A01:2021 – Broken Access Control**.

## 🧪 Steps to Reproduce
The researcher provided the following steps, which we must validate in a **non-production environment** using dedicated test accounts.

1.  **Create two test accounts:**
    * `attacker@triage-test.com` (UserID: `1001`)
    * `victim@triage-test.com` (UserID: `1002`)

2.  **Log in as the attacker:**
    * Log in to the application as `attacker@triage-test.com`.
    * Using a proxy tool (like Burp Suite), navigate to the "My Profile" page.

3.  **Capture the request:**
    * Observe the `GET` request made to fetch the attacker's *own* profile data.
    * **Request:**
        ```http
        GET /api/v1/users/1001 HTTP/1.1
        Host: api.example.com
        Authorization: Bearer eyJhbGciOiJIUzI1Ni...[ATTACKER_JWT]...
        User-Agent: Mozilla/5.0
        ```

4.  **Observe the (normal) response:**
    * **Response (200 OK):**
        ```json
        {
          "id": 1001,
          "username": "attacker",
          "email": "attacker@triage-test.com",
          "phone": "555-0101",
          "address": "123 Attack Lane"
        }
        ```

5.  **Manipulate the request:**
    * Forward the captured request to a tool like Repeater.
    * Change the `id` in the URL from the attacker's ID (`1001`) to the victim's ID (`1002`).

6.  **Confirm the vulnerability:**
    * **Modified Request:**
        ```http
        GET /api/v1/users/1002 HTTP/1.1
        Host: api.example.com
        Authorization: Bearer eyJhbGciOiJIUzI1Ni...[ATTACKER_JWT]...
        User-Agent: Mozilla/5.0
        ```
    * **Vulnerable Response (200 OK):**
        ```json
        {
          "id": 1002,
          "username": "victim",
          "email": "victim@triage-test.com",
          "phone": "555-0102",
          "address": "456 Victim St"
        }
        ```
    * **Verification:** The server responded with a `200 OK` and the **victim's PII**, even though the request was made using the **attacker's** session token. This confirms the bug. A secure application should have returned a `403 Forbidden` or `404 Not Found`.

---

## 🧠 Senior Analyst Commentary
This is a classic, high-impact IDOR. Here’s how you should approach this mentally.

**Your First Questions:**
1.  **What data is being returned?** This is the *most important* question for severity. Is it just a public username (Low impact) or is it PII like the email, phone, and address (High/Critical impact)? The report *claims* PII, but you **must** verify it.

The example above focuses on a "read-only" IDOR, where the vulnerability is in a GET request and its only impact is leaking data.

An IDOR can be far more severe when it affects actions (like POST, PUT, or DELETE requests). This is how an IDOR leads to a full Account Takeover (ATO), often without the attacker ever seeing the victim's original PII.

## 💥 How an IDOR Leads to Account Takeover
Think about any function in an application that changes something for a user. The vulnerability is the same—the endpoint trusts the user-supplied id and doesn't check if the authenticated user is the owner of that id.

Here are the classic examples:

Email Address Change:
An attacker logs into their own account and captures the request to change their email.

Vulnerable Request (PUT): /api/v1/users/1001/update-email

Body: {"email": "attacker-new-email@triage-test.com"}
The Attack: They change the ID in the URL to the victim's ID (1002) but keep their own email in the body.

Modified Request: /api/v1/users/1002/update-email
Body: {"email": "attacker-new-email@triage-test.com"}

Result: The application changes the victim's email address to the attacker's. The attacker never saw the victim's PII, but they can now use the "Forgot Password" flow to take over the account.

Password Reset:
This is even more direct.

Vulnerable Request (POST): /api/v1/users/1001/set-password

Body: {"password": "new-attacker-password123"}

The Attack: The attacker simply changes the user ID to the victim's.

Modified Request: /api/v1/users/1002/set-password

Body: {"password": "new-attacker-password123"}

Result: The victim's password is instantly changed. The attacker can now log in.

🧩 Lesson for Triage
This is why, as an analyst, when you find a "read-only" IDOR on an endpoint like /api/users/{id}, your very next step should be to check for "write-based" IDORs on related endpoints.

If GET /api/users/{id} is vulnerable...

Is PUT /api/users/{id} vulnerable?

Is POST /api/users/{id}/some-action vulnerable?

Is DELETE /api/users/{id} vulnerable?

An IDOR that allows an account takeover is almost always a Critical severity, even if no PII is "leaked" in the process.
```markdown
2.  **What kind of user is the attacker?** The report says "any authenticated user." We must verify this. Use the lowest-privilege test account you have. If the researcher used an *admin* account to view another user, that might be expected behavior. Always test "horizontal" privilege (user-to-user), not just "vertical" (user-to-admin).
3.  **Is the identifier guessable?** The researcher used integer IDs (`1001`, `1002`). This is a "classic" IDOR. If the ID was a non-guessable UUIDv4 (e.g., `a1b2c3d4-e5f6-4a7b-8c9d-1e2f3a4b5c6d`), the severity would be much lower, as an attacker couldn't enumerate users. This report is for a *guessable* integer, which is why it's so dangerous.

**Common False Positives to Watch For:**
* **Public Data:** The endpoint *only* returns public, non-sensitive data (like `username` and `profile_picture_url`). This isn't a PII-leaking IDOR, but rather a "User Enumeration" issue, which is much lower in severity.
* **Non-Guessable IDs:** The researcher shows they can access *one* other user, but they had to find that user's UUID from another part of the app. This is still a bug, but it's not as critical because an attacker can't write a simple script to dump the entire user database.
* **"Self-IDOR":** The researcher only shows a PoC of them accessing their *own* data. Junior analysts sometimes reproduce this with their *own* test account and close it as "Not Applicable." The entire test *requires* two separate accounts.

**When to Ask for More Info:**
* If the researcher's PoC is just a screenshot, *always* ask for the raw `cURL` command or Burp request/response text.
* If they don't specify the user roles, ask: "Thank you for the report. Can you please confirm that you reproduced this using two non-administrative, equal-privilege user accounts?"

---

## ✅ Validation Criteria
For this report to be **Valid** and **High/Critical Severity**, all the following must be true:

* [x] **Authentication is required:** The attacker must be logged in. (If *no* authentication is needed, it's an even more critical "Unauthenticated PII Leakage" bug).
* [x] **Authorization is broken:** The attacker must be a low-privilege user (not an admin, support agent, etc.).
* [x] **Horizontal access is demonstrated:** The attacker (User A) successfully accesses data belonging to a *different, non-privileged* user (User B).
* [x] **Identifier is guessable:** The object reference (`{id}`) is an integer, or something otherwise predictable (e.g., `username`).
* [x] **Sensitive data is exposed:** The response contains PII (email, phone, address, tokens, etc.), not just public data.

---

## 📊 Severity Assessment
This is a **High** severity vulnerability.

* **Impact: High.** The application leaks sensitive PII for *all* users. This is a massive privacy breach, a compliance violation (GDPR, CCPA), and can be used for targeted phishing, identity theft, and account takeovers.
* **Exploitability: Easy.** The vulnerability is trivial to exploit. An attacker can write a simple `for` loop script to enumerate all user IDs (from 1 to 1,000,000) and dump the entire user database in a matter of hours.

> **Formula:** High Impact (PII Breach) + Easy Exploitability (Simple Script) = **High Severity**
>
> *(Note: This would be upgraded to **Critical** if the response included session tokens, passwords, API keys, full credit card numbers, or social security numbers.)*

---

## 💬 Communication Guidance
Our job is to be the professional, calm, and clear hub between the researcher and the engineering team.

### 1. Message to Researcher (On Validation)
> **Subject:** `[HackerOne-Report-12345] Triaged: [High] IDOR on /api/v1/users/{id} allows PII leakage`
>
> Hi [Researcher Name],
>
> Thank you for this excellent and clear report.
>
> We have successfully reproduced the vulnerability in our test environment and confirmed that the `/api/v1/users/{id}` endpoint allows a logged-in user to access the PII of other users.
>
> We have assessed the severity as **High** and escalated this issue to the responsible development team for an immediate fix. We will notify you as soon as a patch is deployed.
>
> We appreciate your contribution to securing our platform.
>
> Best,
> [Your Name]
> Senior Bug Bounty Triage Engineer

### 2. Internal Bug Report (for Developers)
> **Jira Ticket Title:** `[High] [P1] IDOR on /api/v1/users/{id} Leaks User PII (Report-12345)`
>
> **Summary:**
> We have a validated **High** severity IDOR on the v1 user API. Any authenticated user can substitute the `id` in a `GET /api/v1/users/{id}` request to retrieve the full profile (email, phone, address) of *any other user*.
>
> **Root Cause:**
> The endpoint correctly checks for *authentication* (a valid JWT) but fails to perform an *authorization* check (i.e., "does the user ID in the token match the user ID in the URL?").
>
> **Actionable Remediation:**
> The API handler must be updated to implement an authorization check.
>
> **Pseudocode Fix:**
> ```go
> // Get the authenticated user's ID from their session token
> authenticated_user_id = session.get_user_id()
>
> // Get the user ID being requested from the URL
> requested_user_id = url.get_param("id")
>
> // ENFORCE AUTHORIZATION
> if authenticated_user_id != requested_user_id {
>   // Optional: Allow admins
>   // if !session.is_admin() {
>   //   return 403_FORBIDDEN
>   // }
>   return 403_FORBIDDEN // or 404_NOT_FOUND
> }
>
> // If check passes, proceed with function
> user_data = db.find_user(requested_user_id)
> return 200_OK(user_data)
> ```
>
> **PoC / Repro:**
> ```bash
> # Make this request using the session token for user 1001
> curl -H 'Authorization: Bearer [TOKEN_FOR_USER_1001]' '[https://api.example.com/api/v1/users/1002](https://api.example.com/api/v1/users/1002)'
>
> # Vulnerable response will be a 200 OK with user 1002's data
> ```

### 3. Summary for Leadership (Weekly Report)
> * **Finding:** **High Severity IDOR (PII Leakage)**
> * **Description:** A critical flaw was found in our user API allowing any customer to access the personal information (email, phone) of all other customers.
> * **Status:** Triaged, validated, and escalated to the Identity team (JIRA: TICKET-123). Patch is in progress.
> * **Origin:** Bug Bounty Program (External Researcher). No evidence of malicious exploitation found.

---

## 🧩 Lessons for Junior Analysts
* **Trust, but Verify. Every. Single. Time.** This is the core of triage. Never trust a PoC screenshot. Always reproduce it yourself with your own test accounts in a safe environment.
* **Roles are Everything.** A bug's severity lives and dies by the user role. An admin viewing user data is a feature. A user viewing another user's data is a critical bug. You *must* understand the application's roles.
* **You are the Translator.** You are the bridge between the outside world (researchers) and the inside world (developers). Be polite and encouraging to researchers. Be precise, actionable, and non-alarmist for developers. Good communication builds trust and gets bugs fixed faster.
* **Think About Scope.** The researcher reported `/api/v1/users/{id}`. Your next step *after* validation should be to ask:
    * "Does this exist in `/api/v2/users/{id}`?"
    * "Does a similar flaw exist on `/api/v1/orders/{id}`?"
    * "What about `POST` or `PUT` requests? Can I *change* another user's data?"
* This is how you move from a "good" analyst to a "great" one—by finding the *full scope* of the issue and helping the dev team fix the *entire class* of bug, not just this one instance.

---

## 🧰 References
* [OWASP Top 10: A01:2021 - Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
* [PortSwigger (Web Security Academy): What is IDOR?](https://portswigger.net/web-security/access-control/idor)
* [HackerOne: How-To: Insecure Direct Object Reference (IDOR)](https://www.hackerone.com/knowledge-center/how-insecure-direct-object-reference-idor)