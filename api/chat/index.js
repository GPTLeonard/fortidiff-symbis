const MAX_PROMPT_CHARS = 40000;
const DEFAULT_TEMPERATURE = 0.2;

module.exports = async function (context, req) {
  try {
    if (req.method !== "POST") {
      context.res = { status: 405, body: "Method not allowed." };
      return;
    }

    const endpoint = process.env.AZURE_OPENAI_ENDPOINT;
    const apiKey = process.env.AZURE_OPENAI_API_KEY;
    const deployment = process.env.AZURE_OPENAI_DEPLOYMENT;

    if (!endpoint || !apiKey || !deployment) {
      context.res = { status: 500, body: "Server configuration missing." };
      return;
    }

    const body = typeof req.body === "string" ? JSON.parse(req.body) : (req.body || {});
    const prompt = typeof body.prompt === "string" ? body.prompt.trim() : "";

    if (!prompt) {
      context.res = { status: 400, body: "Missing prompt." };
      return;
    }

    if (prompt.length > MAX_PROMPT_CHARS) {
      context.res = { status: 413, body: "Prompt too large." };
      return;
    }

    const baseUrl = endpoint.endsWith("/") ? endpoint : `${endpoint}/`;
    const url = new URL("chat/completions", baseUrl);

    const response = await fetch(url.toString(), {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "api-key": apiKey
      },
      body: JSON.stringify({
        model: deployment,
        temperature: DEFAULT_TEMPERATURE,
        messages: [
          { role: "developer", content: "You are a helpful assistant for internal FortiGate change analysis." },
          { role: "user", content: prompt }
        ]
      })
    });

    if (!response.ok) {
      const errorText = await response.text();
      context.log(`Azure OpenAI error: ${response.status} ${errorText}`);
      context.res = { status: response.status, body: "Upstream AI error." };
      return;
    }

    const data = await response.json();
    const text = data?.choices?.[0]?.message?.content || "";

    context.res = {
      status: 200,
      headers: { "Content-Type": "application/json" },
      body: { text }
    };
  } catch (err) {
    context.log(err);
    context.res = { status: 500, body: "Server error." };
  }
};
