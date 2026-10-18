"use strict";
const button = document.getElementById("continue");
const output = document.getElementById("result");
if (button instanceof HTMLButtonElement && output instanceof HTMLElement) {
    button.onclick = async () => {
        button.disabled = true;
        try {
            if (typeof settings !== "object" ||
                settings === null ||
                !("id" in settings) ||
                typeof settings.id !== "string" ||
                !("csrf" in settings) ||
                typeof settings.csrf !== "string" ||
                !("registration" in settings) ||
                typeof settings.registration !== "boolean")
                throw new Error("settings");
            const path = "/v2/auth/passkeys/";
            const query = `?flow_id=${encodeURIComponent(settings.id)}`;
            const headers = { "x-nds-csrf": settings.csrf };
            const response = await fetch(`${path}options${query}`, {
                headers,
                credentials: "same-origin",
                cache: "no-store",
            });
            if (!response.ok)
                throw new Error("request");
            const options = await response.json();
            if (typeof options !== "object" || options === null || !("publicKey" in options))
                throw new Error("options");
            const parse = settings.registration
                ? PublicKeyCredential.parseCreationOptionsFromJSON
                : PublicKeyCredential.parseRequestOptionsFromJSON;
            if (typeof parse !== "function")
                throw new Error("unsupported");
            // Native WebAuthn JSON/IDL conversion owns validation of its evolving
            // options schema. Keep raw data unknown instead of asserting a duplicate
            // transport type; only an actual PublicKeyCredential may be submitted.
            const publicKey = Reflect.apply(parse, PublicKeyCredential, [options.publicKey]);
            const operation = settings.registration
                ? navigator.credentials.create
                : navigator.credentials.get;
            const credential = await Reflect.apply(operation, navigator.credentials, [
                { publicKey },
            ]);
            if (!(credential instanceof PublicKeyCredential))
                throw new Error("credential");
            const verified = await fetch(`${path}verify${query}`, {
                method: "POST",
                headers: { ...headers, "content-type": "application/json" },
                credentials: "same-origin",
                cache: "no-store",
                body: JSON.stringify(credential.toJSON()),
            });
            if (!verified.ok)
                throw new Error("request");
            output.textContent =
                document.documentElement.lang === "ru"
                    ? "Готово. Вернитесь в приложение NDS."
                    : "Complete. Return to the NDS application.";
        }
        catch {
            output.textContent =
                document.documentElement.lang === "ru"
                    ? "Ключ доступа не подтверждён. Начните вход заново в NDS."
                    : "Passkey was not verified. Start again in NDS.";
        }
    };
}
