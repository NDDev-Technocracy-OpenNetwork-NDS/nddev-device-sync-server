// Unit tests for the passkey continuation page script. The module wires one
// click handler at evaluation time; these tests supply the DOM surface the
// Rust HTML response provides and exercise the flow through that handler.
import { beforeAll, beforeEach, describe, expect, test } from "bun:test";

type FetchCall = { input: string; init: RequestInit };
const calls: FetchCall[] = [];

class Element {
  textContent: string | null = null;
}

class Button extends Element {
  disabled = false;
  onclick: (() => Promise<void>) | null = null;
}

const button = new Button();
const output = new Element();

let fetchResult: () => Response = () =>
  new Response(JSON.stringify({ publicKey: { challenge: "x" } }), { status: 200 });

beforeAll(async () => {
  Object.defineProperty(globalThis, "HTMLElement", { value: Element, configurable: true });
  Object.defineProperty(globalThis, "HTMLButtonElement", { value: Button, configurable: true });
  Object.defineProperty(globalThis, "document", {
    value: {
      getElementById: (id: string) => (id === "continue" ? button : output),
      documentElement: { lang: "en" },
    },
    configurable: true,
  });
  class Credential {
    static parseRequestOptionsFromJSON = (input: unknown) => input;
    static parseCreationOptionsFromJSON = (input: unknown) => input;
    toJSON() {
      return { id: "credential-id" };
    }
  }
  Object.defineProperty(globalThis, "PublicKeyCredential", {
    value: Credential,
    configurable: true,
  });
  Object.defineProperty(globalThis, "navigator", {
    value: {
      credentials: { get: async () => new Credential(), create: async () => new Credential() },
    },
    configurable: true,
  });
  globalThis.fetch = async (input: string | URL | Request, init?: RequestInit) => {
    calls.push({ input: String(input), init: init ?? {} });
    return fetchResult();
  };
  await import("./browser");
});

beforeEach(() => {
  calls.length = 0;
  output.textContent = null;
  button.disabled = false;
  fetchResult = () =>
    new Response(JSON.stringify({ publicKey: { challenge: "x" } }), { status: 200 });
  Object.defineProperty(globalThis, "settings", {
    value: { id: "flow-1", csrf: "token-1", registration: false },
    configurable: true,
    writable: true,
  });
});

function click() {
  expect(button.onclick).not.toBeNull();
  return button.onclick?.() ?? Promise.reject(new Error("no handler"));
}

describe("admitted passkey flow", () => {
  test("requests options and submits the credential under the CSRF header", async () => {
    await click();
    expect(calls).toHaveLength(2);
    expect(calls[0]?.input).toBe("/v2/auth/passkeys/options?flow_id=flow-1");
    expect(calls[0]?.init.headers).toEqual({ "x-nds-csrf": "token-1" });
    expect(calls[1]?.input).toBe("/v2/auth/passkeys/verify?flow_id=flow-1");
    expect(calls[1]?.init.method).toBe("POST");
    expect(calls[1]?.init.body).toBe('{"id":"credential-id"}');
    expect(output.textContent).toBe("Complete. Return to the NDS application.");
    expect(button.disabled).toBe(true);
  });

  test("renders the localized completion under a ru document", async () => {
    Object.defineProperty(globalThis.document, "documentElement", {
      value: { lang: "ru" },
      configurable: true,
    });
    await click();
    expect(output.textContent).toBe("Готово. Вернитесь в приложение NDS.");
    Object.defineProperty(globalThis.document, "documentElement", {
      value: { lang: "en" },
      configurable: true,
    });
  });
});

describe("rejected paths", () => {
  test("malformed flow settings never reach the network", async () => {
    Object.defineProperty(globalThis, "settings", {
      value: { id: 5 },
      configurable: true,
      writable: true,
    });
    await click();
    expect(calls).toHaveLength(0);
    expect(output.textContent).toBe("Passkey was not verified. Start again in NDS.");
  });

  test("a failed options response surfaces the restart message", async () => {
    fetchResult = () => new Response("{}", { status: 500 });
    await click();
    expect(calls).toHaveLength(1);
    expect(output.textContent).toBe("Passkey was not verified. Start again in NDS.");
  });
});
