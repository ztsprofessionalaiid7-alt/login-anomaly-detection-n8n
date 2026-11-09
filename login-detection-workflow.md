# Brute-Force & Anomalous Login Detection: n8n Workflow Code

Importable n8n workflow (n8n Cloud). Copy the JSON below into a file named `login-detection-cloud.json`, then in n8n use **Workflows → Import from File** (or paste it directly onto the canvas with Ctrl+V).

After import, connect your own credentials (nothing secret is stored in this file) and follow the setup steps in the README.

````json
{
  "name": "Brute-force / anomalous login detection & auto-response (n8n Cloud)",
  "nodes": [
    {
      "parameters": {
        "content": "## Setup (n8n Cloud)\n1. Demo uses mock login logs from the Mock Logs node\n2. Credentials (free tiers): Google Gemini, Slack, Postgres (Supabase). Cloudflare is optional\n3. Cloudflare Block IP is DISABLED. Test first, then enable it\n4. Create table login_decisions in Supabase SQL Editor\n5. Click Execute workflow to run all branches",
        "height": 230,
        "width": 480
      },
      "id": "236df7a6-23bd-41ba-825d-f36acd33bd16",
      "name": "Setup notes",
      "type": "n8n-nodes-base.stickyNote",
      "typeVersion": 1,
      "position": [
        -60,
        -180
      ]
    },
    {
      "parameters": {},
      "id": "9cf2c096-70f8-4b33-ad34-303171f20a94",
      "name": "When clicking Execute workflow",
      "type": "n8n-nodes-base.manualTrigger",
      "typeVersion": 1,
      "position": [
        0,
        180
      ]
    },
    {
      "parameters": {
        "jsCode": "const events = [];\nfor (let i = 0; i < 25; i++) events.push({ ip: '203.0.113.5', user: 'user' + (i % 6), status: 'failed' });\nfor (let i = 0; i < 6; i++) events.push({ ip: '198.51.100.7', user: 'admin', status: 'failed' });\nevents.push({ ip: '198.51.100.7', user: 'admin', status: 'success' });\nevents.push({ ip: '192.0.2.10', user: 'alice', status: 'success' });\nfor (let i = 0; i < 5; i++) events.push({ ip: '192.0.2.44', user: 'user' + i, status: 'failed' });\nreturn [{ json: { events } }];"
      },
      "id": "637cee6a-9c85-4637-827b-c22a5d4ae9bd",
      "name": "Mock Logs",
      "type": "n8n-nodes-base.code",
      "typeVersion": 2,
      "position": [
        220,
        180
      ]
    },
    {
      "parameters": {
        "jsCode": "const ALLOWLIST = ['127.0.0.1']; // add your own and office IPs here\nconst BLOCK_AT = 20;   // failed logins that trigger a rule-based block\nconst REVIEW_AT = 5;   // failed logins that go to AI review\nconst map = {};\nfor (const item of $input.all()) {\n  const d = item.json;\n  const events = Array.isArray(d) ? d : (d.events || d.data || [d]);\n  for (const e of events) {\n    const ip = e.ip || e.src_ip || e.ip_address;\n    if (!ip || ALLOWLIST.includes(ip)) continue;\n    const st = String(e.status || e.result || e.outcome || '').toLowerCase();\n    const failed = /fail|denied|invalid|error|unauthor/.test(st);\n    const ok = /success|ok|allow/.test(st) && !failed;\n    const g = map[ip] || (map[ip] = { ip, failed: 0, users: new Set(), saf: false });\n    const u = e.user || e.username || e.email;\n    if (u) g.users.add(u);\n    if (failed) g.failed++;\n    else if (ok && g.failed > 0) g.saf = true;\n  }\n}\nconst out = [];\nfor (const g of Object.values(map)) {\n  const users = [...g.users];\n  const base = {\n    ip: g.ip,\n    failed_count: g.failed,\n    distinct_users: users.length,\n    users: users.slice(0, 5).join(', '),\n    success_after_fail: g.saf\n  };\n  if (g.failed >= BLOCK_AT) {\n    out.push({ json: Object.assign({}, base, { needs_ai: false, action: 'BLOCK', reason: g.failed + ' failed logins in the window (rule)' }) });\n  } else if (g.failed >= REVIEW_AT || (g.failed >= 3 && g.saf)) {\n    out.push({ json: Object.assign({}, base, { needs_ai: true, action: '', reason: '' }) });\n  }\n}\nreturn out;"
      },
      "id": "e8b50930-db05-4052-a2a9-035bebd0aac4",
      "name": "Analyze Logins",
      "type": "n8n-nodes-base.code",
      "typeVersion": 2,
      "position": [
        460,
        180
      ]
    },
    {
      "parameters": {
        "conditions": {
          "options": {
            "caseSensitive": true,
            "leftValue": "",
            "typeValidation": "strict",
            "version": 2
          },
          "conditions": [
            {
              "id": "72d63b51-9c85-4249-86ad-eab4dc52fea9",
              "leftValue": "={{ $json.needs_ai }}",
              "rightValue": "",
              "operator": {
                "type": "boolean",
                "operation": "true",
                "singleValue": true
              }
            }
          ],
          "combinator": "and"
        },
        "options": {}
      },
      "id": "19284b0c-8125-4ae6-9644-702b14b080c4",
      "name": "Needs AI?",
      "type": "n8n-nodes-base.if",
      "typeVersion": 2.2,
      "position": [
        680,
        180
      ]
    },
    {
      "parameters": {
        "promptType": "define",
        "text": "=You are a security analyst reviewing a possible brute-force or anomalous login pattern.\nIP: {{ $json.ip }}\nFailed logins: {{ $json.failed_count }}\nDistinct usernames tried: {{ $json.distinct_users }} ({{ $json.users }})\nSuccessful login after failures: {{ $json.success_after_fail }}\n\nChoose one action: BLOCK (clear attack), MONITOR (suspicious, keep watching), IGNORE (likely a user mistake), ESCALATE (a success after many failures, needs a human). Give a one-sentence reason.",
        "hasOutputParser": true
      },
      "id": "3e2d7a49-2798-4b35-b00a-30c0242ea490",
      "name": "Analyze Pattern",
      "type": "@n8n/n8n-nodes-langchain.chainLlm",
      "typeVersion": 1.5,
      "position": [
        920,
        80
      ],
      "retryOnFail": true,
      "maxTries": 3,
      "waitBetweenTries": 5000
    },
    {
      "parameters": {
        "modelName": "models/gemini-2.5-flash",
        "options": {}
      },
      "id": "34455557-05fb-42e8-b93a-5830509afd04",
      "name": "Google Gemini Chat Model",
      "type": "@n8n/n8n-nodes-langchain.lmChatGoogleGemini",
      "typeVersion": 1,
      "position": [
        900,
        320
      ],
      "credentials": {
        "googlePalmApi": {
          "id": "REPLACE_GEMINI",
          "name": "Google Gemini(PaLM) Api account"
        }
      }
    },
    {
      "parameters": {
        "schemaType": "manual",
        "inputSchema": "{\"type\": \"object\", \"properties\": {\"action\": {\"type\": \"string\", \"enum\": [\"BLOCK\", \"MONITOR\", \"IGNORE\", \"ESCALATE\"]}, \"reason\": {\"type\": \"string\"}}, \"required\": [\"action\", \"reason\"]}"
      },
      "id": "47618ef3-b785-4871-8a9b-20e1017f36f4",
      "name": "Structured Output Parser",
      "type": "@n8n/n8n-nodes-langchain.outputParserStructured",
      "typeVersion": 1.2,
      "position": [
        1100,
        320
      ]
    },
    {
      "parameters": {
        "mode": "runOnceForEachItem",
        "jsCode": "const ctx = $('Analyze Logins').item.json;\nlet r = $json.output;\nif (typeof r === 'string') {\n  try { const m = r.match(/\\{[\\s\\S]*\\}/); r = m ? JSON.parse(m[0]) : {}; } catch (e) { r = {}; }\n}\nr = r || {};\nconst act = String(r.action || '').toUpperCase();\nreturn { json: Object.assign({}, ctx, {\n  action: ['BLOCK', 'MONITOR', 'IGNORE', 'ESCALATE'].includes(act) ? act : 'ESCALATE',\n  reason: String(r.reason || 'AI output could not be parsed').slice(0, 400)\n}) };"
      },
      "id": "89d50853-8ea7-4d24-a111-6f31294645be",
      "name": "Parse AI Decision",
      "type": "n8n-nodes-base.code",
      "typeVersion": 2,
      "position": [
        1280,
        80
      ]
    },
    {
      "parameters": {
        "rules": {
          "values": [
            {
              "conditions": {
                "options": {
                  "caseSensitive": true,
                  "leftValue": "",
                  "typeValidation": "strict",
                  "version": 2
                },
                "conditions": [
                  {
                    "id": "477c2ef8-c8c0-4eb0-a0cb-213bfad7e6b2",
                    "leftValue": "={{ $json.action }}",
                    "rightValue": "BLOCK",
                    "operator": {
                      "type": "string",
                      "operation": "equals"
                    }
                  }
                ],
                "combinator": "and"
              },
              "renameOutput": true,
              "outputKey": "BLOCK"
            },
            {
              "conditions": {
                "options": {
                  "caseSensitive": true,
                  "leftValue": "",
                  "typeValidation": "strict",
                  "version": 2
                },
                "conditions": [
                  {
                    "id": "a8898ca1-773c-4fde-bfe7-63faf3af97b2",
                    "leftValue": "={{ $json.action }}",
                    "rightValue": "MONITOR",
                    "operator": {
                      "type": "string",
                      "operation": "equals"
                    }
                  }
                ],
                "combinator": "and"
              },
              "renameOutput": true,
              "outputKey": "MONITOR"
            },
            {
              "conditions": {
                "options": {
                  "caseSensitive": true,
                  "leftValue": "",
                  "typeValidation": "strict",
                  "version": 2
                },
                "conditions": [
                  {
                    "id": "0fa039f8-e71d-4dc1-84c5-f8f91bcde0b7",
                    "leftValue": "={{ $json.action }}",
                    "rightValue": "IGNORE",
                    "operator": {
                      "type": "string",
                      "operation": "equals"
                    }
                  }
                ],
                "combinator": "and"
              },
              "renameOutput": true,
              "outputKey": "IGNORE"
            },
            {
              "conditions": {
                "options": {
                  "caseSensitive": true,
                  "leftValue": "",
                  "typeValidation": "strict",
                  "version": 2
                },
                "conditions": [
                  {
                    "id": "4ad30a98-528d-4b56-bda4-7dc0b27eba12",
                    "leftValue": "={{ $json.action }}",
                    "rightValue": "ESCALATE",
                    "operator": {
                      "type": "string",
                      "operation": "equals"
                    }
                  }
                ],
                "combinator": "and"
              },
              "renameOutput": true,
              "outputKey": "ESCALATE"
            }
          ]
        },
        "options": {}
      },
      "id": "1506b617-7170-4639-a543-832ee89d5135",
      "name": "Switch",
      "type": "n8n-nodes-base.switch",
      "typeVersion": 3,
      "position": [
        1500,
        180
      ]
    },
    {
      "parameters": {
        "method": "POST",
        "url": "https://api.cloudflare.com/client/v4/accounts/YOUR_ACCOUNT_ID/firewall/access_rules/rules",
        "authentication": "genericCredentialType",
        "genericAuthType": "httpHeaderAuth",
        "sendBody": true,
        "contentType": "json",
        "specifyBody": "json",
        "jsonBody": "={{ JSON.stringify({ mode: 'block', configuration: { target: 'ip', value: $json.ip }, notes: 'n8n auto-block: ' + $json.reason }) }}",
        "options": {}
      },
      "id": "544d4a31-f810-4d7c-ac22-8195d78b3122",
      "name": "Cloudflare Block IP",
      "type": "n8n-nodes-base.httpRequest",
      "typeVersion": 4.2,
      "position": [
        1780,
        20
      ],
      "credentials": {
        "httpHeaderAuth": {
          "id": "REPLACE_CF",
          "name": "Cloudflare Header Auth"
        }
      },
      "onError": "continueRegularOutput",
      "disabled": true
    },
    {
      "parameters": {
        "select": "channel",
        "channelId": {
          "__rl": true,
          "value": "security-alerts",
          "mode": "name"
        },
        "text": ":lock: *{{ $json.action }}* for IP `{{ $json.ip }}`\nFailed logins: {{ $json.failed_count }} | Usernames tried: {{ $json.distinct_users }} ({{ $json.users }})\nSuccess after failures: {{ $json.success_after_fail }}\nReason: {{ $json.reason }}",
        "otherOptions": {}
      },
      "id": "fb9491ac-a702-4d2f-b1ae-f90c17f5633f",
      "name": "Slack Alert",
      "type": "n8n-nodes-base.slack",
      "typeVersion": 2.3,
      "position": [
        1780,
        200
      ],
      "credentials": {
        "slackApi": {
          "id": "REPLACE_SLACK",
          "name": "Slack account"
        }
      },
      "onError": "continueRegularOutput"
    },
    {
      "parameters": {
        "operation": "insert",
        "schema": {
          "__rl": true,
          "value": "public",
          "mode": "list",
          "cachedResultName": "public"
        },
        "table": {
          "__rl": true,
          "value": "login_decisions",
          "mode": "name"
        },
        "columns": {
          "mappingMode": "defineBelow",
          "value": {
            "ip": "={{ $json.ip }}",
            "failed_count": "={{ $json.failed_count }}",
            "distinct_users": "={{ $json.distinct_users }}",
            "action": "={{ $json.action }}",
            "reason": "={{ $json.reason }}"
          },
          "matchingColumns": [],
          "schema": [
            {
              "id": "ip",
              "displayName": "ip",
              "required": false,
              "defaultMatch": false,
              "display": true,
              "type": "string",
              "canBeUsedToMatch": true
            },
            {
              "id": "failed_count",
              "displayName": "failed_count",
              "required": false,
              "defaultMatch": false,
              "display": true,
              "type": "number",
              "canBeUsedToMatch": true
            },
            {
              "id": "distinct_users",
              "displayName": "distinct_users",
              "required": false,
              "defaultMatch": false,
              "display": true,
              "type": "number",
              "canBeUsedToMatch": true
            },
            {
              "id": "action",
              "displayName": "action",
              "required": false,
              "defaultMatch": false,
              "display": true,
              "type": "string",
              "canBeUsedToMatch": true
            },
            {
              "id": "reason",
              "displayName": "reason",
              "required": false,
              "defaultMatch": false,
              "display": true,
              "type": "string",
              "canBeUsedToMatch": true
            }
          ]
        },
        "options": {}
      },
      "id": "4ebea50f-446d-49bc-bd37-e99bb018a04f",
      "name": "Log Decision",
      "type": "n8n-nodes-base.postgres",
      "typeVersion": 2.5,
      "position": [
        1780,
        380
      ],
      "credentials": {
        "postgres": {
          "id": "REPLACE_PG",
          "name": "Postgres account"
        }
      }
    }
  ],
  "connections": {
    "When clicking Execute workflow": {
      "main": [
        [
          {
            "node": "Mock Logs",
            "type": "main",
            "index": 0
          }
        ]
      ]
    },
    "Mock Logs": {
      "main": [
        [
          {
            "node": "Analyze Logins",
            "type": "main",
            "index": 0
          }
        ]
      ]
    },
    "Analyze Logins": {
      "main": [
        [
          {
            "node": "Needs AI?",
            "type": "main",
            "index": 0
          }
        ]
      ]
    },
    "Needs AI?": {
      "main": [
        [
          {
            "node": "Analyze Pattern",
            "type": "main",
            "index": 0
          }
        ],
        [
          {
            "node": "Switch",
            "type": "main",
            "index": 0
          }
        ]
      ]
    },
    "Google Gemini Chat Model": {
      "ai_languageModel": [
        [
          {
            "node": "Analyze Pattern",
            "type": "ai_languageModel",
            "index": 0
          }
        ]
      ]
    },
    "Structured Output Parser": {
      "ai_outputParser": [
        [
          {
            "node": "Analyze Pattern",
            "type": "ai_outputParser",
            "index": 0
          }
        ]
      ]
    },
    "Analyze Pattern": {
      "main": [
        [
          {
            "node": "Parse AI Decision",
            "type": "main",
            "index": 0
          }
        ]
      ]
    },
    "Parse AI Decision": {
      "main": [
        [
          {
            "node": "Switch",
            "type": "main",
            "index": 0
          }
        ]
      ]
    },
    "Switch": {
      "main": [
        [
          {
            "node": "Cloudflare Block IP",
            "type": "main",
            "index": 0
          },
          {
            "node": "Slack Alert",
            "type": "main",
            "index": 0
          },
          {
            "node": "Log Decision",
            "type": "main",
            "index": 0
          }
        ],
        [
          {
            "node": "Slack Alert",
            "type": "main",
            "index": 0
          },
          {
            "node": "Log Decision",
            "type": "main",
            "index": 0
          }
        ],
        [
          {
            "node": "Log Decision",
            "type": "main",
            "index": 0
          }
        ],
        [
          {
            "node": "Slack Alert",
            "type": "main",
            "index": 0
          },
          {
            "node": "Log Decision",
            "type": "main",
            "index": 0
          }
        ]
      ]
    }
  },
  "pinData": {},
  "active": false,
  "settings": {
    "executionOrder": "v1"
  },
  "tags": []
}
````
