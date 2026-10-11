# trace.jq — renders the events of a DEV-TEST site as one timeline per request (issue #329).
#
#   jq -rs --rawfile reasons reasons.tsv --arg only "<trace id or empty>" -f trace.jq events.jsonl ...
#
# An event is one JSON line written by a machine about a request it saw:
#   agent   (M3)  the request as the agent made it, and the answers it got
#   brokerd (M1)  the cell's decision: who asked (certificate), what, allow or deny, why
#   transport (M1) a connection that never became a request (a refused TLS handshake)
#   pepd, app (M2) pepd's verdict as returned to the application, and what the application did with it
# Events of one request share a trace id (header X-TBP-Trace-Id). A request that carries none — someone using curl
# directly — has no timeline of its own: it is listed under "without a trace id", one line per event.

def secs:
  if . == null then 0
  else ((.[0:19] + "Z") | fromdateiso8601)
       + (if (length > 21) then (("0." + .[20:(length - 1)]) | tonumber) else 0 end)
  end;

def offset($t0):
  ((((.ts | secs) - $t0) * 1000) | round) as $ms
  | "+\($ms / 1000 | floor).\(($ms % 1000) | tostring | ("000" + .)[-3:])s";

def pad($n): . + (" " * ([$n - length, 0] | max));

# the order of a request's lines follows the steps it went through, not a comparison of three machines' clocks
def rank:
  if .component == "agent" and .stage == "request" and .outcome == "emitted" then 10
  elif .component == "transport" then 15
  elif .component == "brokerd" then 20
  elif .component == "agent" and .stage == "answer" and .hop != "app" and ((.detail // "") | contains("the application answered") | not) then 30
  elif .component == "agent" and .stage == "request" then 40
  elif .component == "app" and .stage == "request" then 50
  elif .component == "pepd" then 60
  elif .component == "app" then 70
  elif .component == "agent" then 80
  else 90 end;

def mach:
  if .component == "agent" then "M3"
  elif .component == "brokerd" or .component == "transport" then "M1"
  elif .component == "pepd" or .component == "app" then "M2"
  else "?" end;

def catalog:
  ($reasons | split("\n") | map(select(length > 0 and (startswith("#") | not)) | split("\t"))
   | map({key: .[0], value: {where: .[1], meaning: (.[2] // "")}}) | from_entries);

def why($r):
  if ($r == null or $r == "") then ""
  else (catalog[$r] // null) as $c
       | if $c == null then $r else "\($r) — \($c.where): \($c.meaning)" end
  end;

def action_of:
  (.intent // "") as $i
  | (try ($i | fromjson | "\(.action) \(.resource)") catch $i);

def describe:
  if .component == "agent" and .stage == "request" then
    (.detail // "") + (if .peer_cn then "   [certificate: \(.peer_cn)]" else "" end)
  elif .component == "agent" then
    "got: \(.outcome)" + (if .reason then " \(.reason)" else "" end) + (if (.detail // "") != "" and .detail != "answer received from the cell" then " (\(.detail))" else "" end)
  elif .component == "brokerd" and .stage == "decision" then
    "\(.outcome | ascii_upcase) \(.reason)"
    + "   [\(.subject // "?") · \(action_of) · certificate \(.peer_cn // "none") · \(.transport // "?")"
    + (if .peer then " from \(.peer)" else "" end)
    + (if .elapsed_us then " · \(.elapsed_us / 1000 | . * 10 | round / 10) ms" else "" end)
    + (if .jti then " · jti \(.jti[0:8])…" else "" end) + "]"
  elif .component == "brokerd" then
    "REFUSED \(.reason)\(if .detail then " (\(.detail))" else "" end)   [certificate \(.peer_cn // "none") · \(.transport // "?")\(if .peer then " from \(.peer)" else "" end)]"
  elif .component == "transport" then
    "\(.detail // .reason)"
  elif .component == "pepd" then
    "verdict \(.outcome) \(.reason // "")   [posture \(.mode // "?") · forwarded \(.forwarded // "?")\(if .elapsed_us then " · \(.elapsed_us / 1000 | . * 10 | round / 10) ms" else "" end)]"
  elif .component == "app" and .stage == "request" then
    "request received: \(.intent // "?") \(.detail // "")" + (if .peer then "   [from \(.peer)]" else "" end)
  elif .component == "app" then
    (.outcome | ascii_upcase) + (if .reason then " \(.reason)" else "" end) + (if .detail then "   [HTTP \(.detail)]" else "" end)
  else (.stage // "") end;

def who:
  if .component == "agent" then "agent"
  else .component end;

# the end of a request, in one line
def ending($evs):
  ($evs | map(select(.component == "app" and .stage == "outcome")) | last) as $app
  | ($evs | map(select(.component == "pepd")) | last) as $pepd
  | ($evs | map(select(.component == "brokerd")) | last) as $cell
  | ($evs | map(select(.component == "agent" and .stage == "answer")) | last) as $got
  | ($evs | map(select(.component == "transport")) | last) as $tls
  | if $tls != null then "REJECTED at the TLS handshake (M1) — \(why("tls-handshake-refused"))"
    elif $app != null and $app.outcome == "executed" and $pepd != null and $pepd.outcome == "deny" then
      "EXECUTED — although pepd's verdict was \($pepd.reason): in the monitor posture pepd records and blocks nothing"
    elif $app != null and $app.outcome == "executed" then "EXECUTED"
    elif $app != null and $pepd != null and $pepd.forwarded == false then
      "REJECTED by pepd (M2) — \(why($pepd.reason // $app.reason))"
    elif $app != null then "REJECTED by the application (M2) — \(why($app.reason))"
    elif $cell != null and $cell.outcome == "deny" then "REJECTED by the cell (M1) — \(why($cell.reason))"
    elif $got != null and $got.outcome == "deny" and ($got.reason // "") != "" then "REJECTED — \(why($got.reason))"
    elif $cell != null and $cell.outcome == "allow" then "TOKEN ISSUED by the cell, not presented to the application (as far as these files show)"
    else "INCOMPLETE — no end seen: the machines that took part have not all been given to this command" end;

def timeline($evs):
  ($evs | map(.ts | secs) | min) as $t0
  | ($evs | sort_by([rank, .ts])) as $sorted
  | ($sorted | map(select(.component == "agent" and .stage == "request")) | first // null) as $first
  | "\($evs[0].trace_id)   \($first.detail // ($sorted | map(select(.component == "brokerd" and .stage == "decision")) | first | action_of) // "")",
    ($sorted[] | "  \(offset($t0))  \(mach)  \(who | pad(8))  \(describe)"),
    "  → \(ending($sorted))",
    "";

# a refused TLS handshake never becomes a request on the cell, so it carries no trace id: it is attached to the agent's
# own record of a request made without a client certificate when they are within 3 seconds, and says so.
def explained_by($g):
  ($g | map(select(.component == "agent" and .stage == "request" and ((.detail // "") | contains("no client certificate")))) | first) as $a
  | $a != null and ((((.ts | secs) - ($a.ts | secs)) | fabs) < 3);

(map(select(.ts != null and .component != null))) as $all
| ($all | map(select(.trace_id != null and .trace_id != "")) | group_by(.trace_id)) as $raw
| ($all | map(select(.component == "transport"))) as $tls
| ($raw | map(. as $g
    | ($g | map(select(.component == "agent" and .stage == "request")) | first) as $a
    | $g + ($tls | map(select(explained_by($g))) | map(. + {detail: ((.detail // "") + " (matched to this request by time; the cell logs whole seconds)"), shown_ts: $a.ts}))))
    as $withtls
| ($withtls | map(.[] | select(.component == "transport") | .ts + (.peer // "")) | unique) as $attached
| ($withtls | map(map(if .shown_ts then .ts = .shown_ts else . end))) as $shown
| ($shown | map(select($only == "" or .[0].trace_id == $only)) | sort_by(.[0].ts)) as $groups
| ($all | map(select((.trace_id == null or .trace_id == "") and $only == "" and ((.ts + (.peer // "")) as $k | ($attached | index($k)) == null))) | sort_by(.ts)) as $loose
| ( if ($groups | length) == 0 and ($loose | length) == 0 then "no request recorded yet" else empty end ),
  ($groups[] | timeline(.)),
  ( if ($loose | length) > 0 then
      "without a trace id (a client that did not send X-TBP-Trace-Id — curl, a scanner, a red team):",
      ($loose[] | "  \(.ts[11:23])  \(mach)  \(who | pad(9))  \(describe)")
    else empty end )
