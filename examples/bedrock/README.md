# Checking an AWS Bedrock Agents deployment

[Amazon Bedrock Agents](https://docs.aws.amazon.com/bedrock/latest/userguide/agents.html)
builds an assistant from one or more agents. A **supervisor** routes work to
**collaborator** agents; each agent reaches the outside world through **action
groups** (a Lambda, or RETURN_CONTROL) and reads **knowledge bases**. Each
piece is configured on its own.

Sherlock checks the pieces **together**: whether web text one agent crawls can
end up acting through a payments account another agent holds, through the
messages the agents exchange.

```bash
python3 agentcheck.py check examples/bedrock/fleet.policy --bedrock examples/bedrock
```

## This example

A customer-support deployment:

- `supervisor` (multi-agent SUPERVISOR, with SESSION_SUMMARY memory and a guardrail)
  routes each request and takes the user's turns.
- `researcher` reads a knowledge base `support_wiki` filled by a **web crawler**
  (so its contents are attacker-written) and looks up `store:customer_db` through
  an action group **without** confirmation.
- `assistant` emails through `sink:ses` (SES, no confirmation) and can act through
  `acct:api.payments.example.com` only through two functions that **require
  confirmation** (`issue_refund`, `close_account`).

| Rule | Result | Why |
|---|---|---|
| Customer PII never leaves the deployment | FAIL (0 hacked, 0 approvals) | the researcher reads the customer DB and the honest chain researcher → supervisor → assistant → SES carries it out |
| Card data never leaves, even with one confirmation | FAIL (0 hacked, 1 approval) | one refund confirmation lets the assistant read billing data, which the email path then leaks |
| Web content never acts through the payments account | PASS | the payments account is reachable only behind a confirmation |
| Web content reaches payments only behind a confirmation | FAIL (0 hacked, 1 approval) | crawled web text steers the chain; one confirmation then acts on the account |
| The supervisor's session memory is never attacker-controlled | FAIL (0 hacked, 0 approvals) | untrusted user input poisons the session-summary memory |

The two payments rules differ only in the approval budget, which is how the
`requireConfirmation` gate shows up: it holds at zero approvals, and breaks with one.

## The export

`load_bedrock` reads a directory of JSON exported from the Bedrock control-plane
API (`aws bedrock-agent get-agent`, `list-agent-action-groups`,
`list-agent-collaborators`, `get-knowledge-base`, ...), grouped into
subdirectories: `agents/`, `action-groups/`, `collaborators/`,
`knowledge-bases/`, `agent-knowledge-bases/`.

`rights.json` is the one file that is **not** a Bedrock API output. Bedrock's
agent config does not record what an action group's Lambda may touch — that
lives in the Lambda's IAM role — so `rights.json` declares each action group's
effect on resources (`store:`, `kb:`, `sink:`, `net:`, `acct:`). An action group
with no declared rights is modeled conservatively as able to read every store
and reach every sink. See the header of `bedrock.py` for the full mapping.
