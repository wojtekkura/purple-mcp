// Purple AI tool: `purple_ai`. Port of tools/purple_ai.py + libs/purple_ai/client.py.
//
// Thin wrapper around SentinelOne Purple AI. The Python source builds a single
// `purpleLaunchQuery` GraphQL request (NATURAL_LANGUAGE input over the last 24h),
// fires it once, and parses MESSAGE vs POWER_QUERY result types. We reproduce the
// exact query string and variable shape here, sourcing identity from ctx.purpleAi.
//
// Notes on the port:
//   - Python's nested asyncio.run / tenacity retry is irrelevant in the Worker:
//     the shared PurpleClient.graphql() does one POST and handles retry/errors.
//   - User-Agent is set by PurpleClient (graphql_client_base parity), so we do not
//     thread userAgent through here; the GraphQL userDetails.userAgent/buildDate/
//     buildHash are sent as null, matching the Python __main__ usage where those
//     are None and json.dumps(None) -> `null`.
//   - Where Python returned a bare string, we return a structured `data` block so
//     the agent gets the result type + any generated PowerQuery + metadata.

import { ToolDescriptor } from "../mcp.js";
import { ToolFn, ToolResult, optionalString, requireString, runTool } from "../tool-base.js";
import { clampToFitBytes } from "../envelope.js";

// Ported verbatim from tools/purple_ai.py PURPLE_AI_DESCRIPTION (condensed).
const PURPLE_AI_DESCRIPTION =
  "Interact with SentinelOne's Purple AI, a cybersecurity assistant that investigates threats, " +
  "generates PowerQueries, and answers questions about SentinelOne. It understands natural language " +
  "and either answers in plain language (MESSAGE) or returns a generated PowerQuery (POWER_QUERY).\n\n" +
  "Purple AI can: generate/explain PowerQueries for threat hunting; answer using threat intelligence " +
  "and behavioral signals; explore user/process/network/file activity; investigate MITRE TTPs, " +
  "ransomware, lateral movement; and answer questions about SentinelOne capabilities.\n\n" +
  "Purple AI can't: access active alerts (use the Alerts tools); modify configs or endpoints; or RUN a " +
  "PowerQuery (use the `powerquery` tool to run a PQ that Purple AI returns).\n\n" +
  "Ask good questions: be descriptive (process names, paths, domains, ports, usernames), focused, and " +
  "scoped (time range, OS, endpoint type). Start with verbs like show/find/list/search. " +
  "Examples: 'Show me PowerShell processes that connected to external IPs', " +
  "'Find unsigned processes that accessed lsass.exe', 'Are there any reverse SSH tunnels from public IPs?'. " +
  "Do NOT say 'Generate a PowerQuery to ...' for investigative questions — just say what you're looking " +
  "for (GOOD: 'Is APT-1337 in my environment?'). The one exception: to explicitly request a query, say " +
  "'Generate a PowerQuery to detect ...'.";

// GraphQL request string, ported verbatim from client._build_graphql_request.
// $input is supplied as a GraphQL variable; all other dynamic values are inlined
// via JSON.stringify() (the TS equivalent of Python json.dumps) to safely escape
// quotes/backslashes/unicode and to render null for absent values.
function buildGraphqlRequest(opts: {
  startTime: number;
  endTime: number;
  baseUrl: string | null;
  version: string | null;
  scalyrAccountId: string | null;
  scalyrTeamToken: string | null;
  sessionId: string | null;
  emailAddress: string | null;
  userAgent: string | null;
  buildDate: string | null;
  buildHash: string | null;
  conversationId: string;
}): string {
  const j = (v: unknown): string => JSON.stringify(v ?? null);
  return `\
    query SimpleTestQuery($input: String!) {
        purpleLaunchQuery(
            request: {
                isAsync: false
                contentType: NATURAL_LANGUAGE
                consoleDetails: {
                    baseUrl: ${j(opts.baseUrl)}
                    version: ${j(opts.version)}
                }
                conversation: { id: ${j(opts.conversationId)}, messages: [], entitlements: null }
                inputContent: {
                    userInput: $input
                    displayedTimeRange: { start: ${opts.startTime}, end: ${opts.endTime} }
                    viewSelector: EDR
                    contentType: NATURAL_LANGUAGE
                    userDetails: {
                        accountId: ${j(opts.scalyrAccountId)}
                        teamToken: ${j(opts.scalyrTeamToken)}
                        sessionId: ${j(opts.sessionId)}
                        emailAddress: ${j(opts.emailAddress)}
                        userAgent: ${j(opts.userAgent)}
                        buildDate: ${j(opts.buildDate)}
                        buildHash: ${j(opts.buildHash)}
                    }
                }
            }
        ) {
            result {
                message
                summary
                powerQuery {
                    query
                    timeRange {
                        start
                        end
                    }
                    viewSelector
                }
                starRule
                suggestedActions {
                    payload
                    label
                    actionId
                }
                suggestedQuestions {
                    powerQuery
                    question
                }
                maskedMetadata
            }
            resultType
            status {
                state
                error {
                    errorDetail
                    errorType
                    origin
                }
            }
            stepsCompleted
            token
        }
    }
`;
}

function asRecord(v: unknown): Record<string, unknown> | null {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

const purple_ai: ToolFn = (ctx, args) =>
  runTool("POST <purple ai graphql> purpleLaunchQuery", async (): Promise<ToolResult> => {
    const query = requireString(args.query, "query");

    // conversation_id passthrough for conversation continuity. Python generates
    // "PURPLE-MCP" + 10 random chars per call; allow the agent to pin one, else mint.
    const conversationId =
      optionalString(args.conversation_id, "conversation_id") ?? `PURPLE-MCP${crypto.randomUUID()}`;

    // 24h displayed time range in ms, matching client._generate_query.
    const endTime = Date.now();
    const startTime = endTime - 24 * 60 * 60 * 1000;

    const gql = buildGraphqlRequest({
      startTime,
      endTime,
      baseUrl: null, // consoleDetails.baseUrl not exposed on ctx.purpleAi
      version: ctx.purpleAi.consoleVersion,
      scalyrAccountId: ctx.purpleAi.accountId,
      scalyrTeamToken: ctx.purpleAi.teamToken,
      sessionId: ctx.purpleAi.sessionId,
      emailAddress: ctx.purpleAi.emailAddress,
      userAgent: null, // PurpleClient sets the HTTP User-Agent header
      buildDate: null,
      buildHash: null,
      conversationId,
    });

    // Single GraphQL POST; PurpleClient.graphql throws on HTTP/GraphQL errors and
    // returns the unwrapped `data` object.
    const data = await ctx.client.graphql(ctx.endpoints.consoleGraphql, gql, { input: query });

    const purple = asRecord(data["purpleLaunchQuery"]);
    if (!purple) {
      // Mirror Python's "Missing purpleLaunchQuery in response" path as a structured result.
      return {
        data: {
          conversation_id: conversationId,
          result_type: null,
          error: "Missing purpleLaunchQuery in response.",
        },
      };
    }

    // Surface a Purple-AI-side status error (Python returns None type with the error).
    const status = asRecord(purple["status"]);
    const statusError = status ? asRecord(status["error"]) : null;
    if (statusError) {
      const errorType = typeof statusError["errorType"] === "string" ? statusError["errorType"] : null;
      return {
        data: {
          conversation_id: conversationId,
          result_type: null,
          // Python special-cases UNKNOWN with a "please rephrase" hint.
          message:
            errorType === "UNKNOWN"
              ? "Purple AI encountered an error with this question. Please try rephrasing your question and submitting it again."
              : null,
          error: statusError,
          state: status ? (status["state"] ?? null) : null,
        },
      };
    }

    const resultType = typeof purple["resultType"] === "string" ? (purple["resultType"] as string) : null;
    const result = asRecord(purple["result"]);

    // Extract message + PowerQuery exactly as Python's ask_purple does, but keep
    // both plus metadata in the structured payload.
    const message =
      result && result["message"] != null ? String(result["message"]) : null;
    const summary = result && result["summary"] != null ? String(result["summary"]) : null;

    const powerQueryObj = result ? asRecord(result["powerQuery"]) : null;
    const powerQuery =
      powerQueryObj && powerQueryObj["query"] != null ? String(powerQueryObj["query"]) : null;

    // `answer` mirrors Python's single-string return: PQ text for POWER_QUERY,
    // else the message text.
    const answer =
      resultType === "POWER_QUERY" ? (powerQuery ?? "") : (message ?? "");

    // Metadata blocks can be large (suggestedQuestions/Actions/maskedMetadata);
    // clamp the suggested-questions list to stay under the byte budget.
    const suggestedQuestionsRaw = Array.isArray(result?.["suggestedQuestions"])
      ? (result!["suggestedQuestions"] as unknown[])
      : [];
    const suggestedActions = Array.isArray(result?.["suggestedActions"])
      ? (result!["suggestedActions"] as unknown[])
      : [];

    const payloadBase = {
      conversation_id: conversationId,
      result_type: resultType,
      answer,
      message,
      summary,
      power_query: powerQuery
        ? {
            query: powerQuery,
            time_range: powerQueryObj ? (powerQueryObj["timeRange"] ?? null) : null,
            view_selector: powerQueryObj ? (powerQueryObj["viewSelector"] ?? null) : null,
          }
        : null,
      star_rule: result ? (result["starRule"] ?? null) : null,
      suggested_actions: suggestedActions,
      masked_metadata: result ? (result["maskedMetadata"] ?? null) : null,
      steps_completed: purple["stepsCompleted"] ?? null,
    };

    const { kept, truncated } = clampToFitBytes(
      suggestedQuestionsRaw,
      (items) => ({ ...payloadBase, suggested_questions: items }),
    );

    return {
      data: {
        ...payloadBase,
        suggested_questions: kept,
        suggested_questions_truncated: truncated,
      },
    };
  });

export const PURPLE_AI_TOOLS: Record<string, ToolFn> = {
  purple_ai,
};

export const PURPLE_AI_DESCRIPTORS: ToolDescriptor[] = [
  {
    name: "purple_ai",
    description: PURPLE_AI_DESCRIPTION,
    inputSchema: {
      type: "object",
      properties: {
        query: {
          type: "string",
          description:
            "The natural-language question to ask Purple AI. Be descriptive and focused; say what you're looking for rather than asking it to 'generate a PowerQuery' (unless you explicitly want a query).",
        },
        conversation_id: {
          type: "string",
          description:
            "Optional conversation identifier to continue a prior Purple AI conversation. If omitted, a new one is generated per call.",
        },
      },
      required: ["query"],
      additionalProperties: false,
    },
  },
];
