import { useState, type FormEvent } from "react";
import { useMutation } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { api, ApiError, type MfaLoginResponse } from "../api";
import {
  CredentialsForm,
  ErrorAlert,
  Field,
  LoginError,
  LoginLayout,
  MethodInfo,
  Notice,
  useGoToDashboard,
} from "../components";

type Step =
  | { kind: "credentials"; notice?: string }
  | { kind: "verify"; challenge: MfaLoginResponse }
  | { kind: "recovery-codes"; codes: string[] };

export function LoginMfaPage() {
  const [step, setStep] = useState<Step>({ kind: "credentials" });
  const goToDashboard = useGoToDashboard();

  const login = useMutation({
    mutationFn: api.mfaLogin,
    onSuccess: (challenge) => setStep({ kind: "verify", challenge }),
  });

  let body;
  switch (step.kind) {
    case "credentials":
      body = (
        <>
          {step.notice ? <Notice>{step.notice}</Notice> : null}
          <CredentialsForm submitLabel="Continue" pending={login.isPending} onSubmit={(c) => login.mutate(c)} />
          <LoginError error={login.error} />
          <p className="muted small">
            No account yet? <Link to="/register">Register</Link>
          </p>
        </>
      );
      break;
    case "verify":
      body = (
        <VerifyStep
          challenge={step.challenge}
          onRestart={(notice) => {
            login.reset();
            setStep({ kind: "credentials", notice });
          }}
          onAuthenticated={(recoveryCodes) => {
            if (recoveryCodes && recoveryCodes.length > 0) {
              setStep({ kind: "recovery-codes", codes: recoveryCodes });
            } else {
              void goToDashboard();
            }
          }}
        />
      );
      break;
    case "recovery-codes":
      body = <RecoveryCodes codes={step.codes} onContinue={() => void goToDashboard()} />;
      break;
  }

  return (
    <LoginLayout
      title="MFA login (TOTP)"
      lead="Password plus a time-based one-time code from an authenticator app such as Google Authenticator, 1Password or Authy."
      info={
        <MethodInfo
          steps={[
            "You submit your username and password. If they're valid the server starts a short-lived MFA challenge (kept in an httpOnly cookie) — no session yet.",
            "First time: the server generates a TOTP secret and shows it as a QR code to scan into your authenticator app.",
            "You enter the current 6-digit code; the server checks it against the secret (RFC 6238, 30-second steps).",
            "After enrollment you get one-time recovery codes; then a session is created and you land on the dashboard.",
          ]}
          controls={[
            "RFC 6238 TOTP (6 digits, 30-second period, small clock-skew window)",
            "TOTP secret encrypted at rest with AES-256-GCM",
            "Replay protection: an accepted code cannot be used again",
            "Limited verification attempts per challenge; short-lived challenge",
            "Recovery codes are hashed and single-use",
            "Password step uses argon2id, generic errors, lockout and rate limiting",
          ]}
        />
      }
    >
      {body}
    </LoginLayout>
  );
}

function VerifyStep({
  challenge,
  onRestart,
  onAuthenticated,
}: {
  challenge: MfaLoginResponse;
  onRestart: (notice?: string) => void;
  onAuthenticated: (recoveryCodes: string[] | undefined) => void;
}) {
  const enrolling = challenge.status === "enrollment_required";
  const [code, setCode] = useState("");
  const [useRecoveryCode, setUseRecoveryCode] = useState(false);

  const verify = useMutation({
    mutationFn: api.mfaVerify,
    onSuccess: (res) => onAuthenticated(res.recoveryCodes),
    onError: (err) => {
      if (err instanceof ApiError && err.error === "challenge_expired") {
        onRestart("Your sign-in attempt expired. Please enter your username and password again.");
      } else if (err instanceof ApiError && err.attemptsRemaining === 0) {
        onRestart("Too many incorrect codes. Please sign in again.");
      } else {
        setCode("");
      }
    },
  });

  function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    verify.mutate({ code: code.trim() });
  }

  const attemptsRemaining = verify.error instanceof ApiError ? verify.error.attemptsRemaining : undefined;

  return (
    <div className="stack">
      {challenge.status === "enrollment_required" ? (
        <div className="enroll">
          <p>
            <strong>Set up two-factor authentication.</strong> Scan this QR code with your authenticator app, then enter
            the 6-digit code it shows.
          </p>
          <img className="qr" src={challenge.qrCodeDataUrl} alt="QR code for your authenticator app" width={200} height={200} />
          <details>
            <summary>Can't scan? Enter the key manually</summary>
            <code className="secret">{challenge.secret}</code>
          </details>
        </div>
      ) : (
        <p>
          <strong>Two-factor authentication.</strong> Enter the 6-digit code from your authenticator app.
        </p>
      )}

      <form className="form" onSubmit={handleSubmit}>
        {useRecoveryCode ? (
          <Field label="Recovery code" hint="Format xxxxx-xxxxx. Each recovery code works only once.">
            <input
              key="recovery"
              name="recoveryCode"
              autoComplete="off"
              autoCapitalize="none"
              spellCheck={false}
              className="mono"
              required
              autoFocus
              value={code}
              onChange={(e) => setCode(e.target.value)}
            />
          </Field>
        ) : (
          <Field
            label="Authentication code"
            hint={enrolling ? undefined : "Lost your device? A recovery code also works."}
          >
            <input
              key="totp"
              name="code"
              autoComplete="one-time-code"
              inputMode="numeric"
              pattern="[0-9]{6}"
              maxLength={6}
              placeholder="123456"
              className="mono code-input"
              required
              autoFocus
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
            />
          </Field>
        )}

        <ErrorAlert error={verify.error}>
          {attemptsRemaining !== undefined && attemptsRemaining > 0 ? (
            <p>
              {attemptsRemaining} attempt{attemptsRemaining === 1 ? "" : "s"} remaining.
            </p>
          ) : null}
        </ErrorAlert>

        <button type="submit" className="btn btn-primary" disabled={verify.isPending}>
          {verify.isPending ? "Verifying…" : enrolling ? "Verify and enable MFA" : "Verify"}
        </button>
      </form>

      <div className="button-row">
        {!enrolling && (
          <button
            type="button"
            className="btn btn-link"
            onClick={() => {
              setUseRecoveryCode((v) => !v);
              setCode("");
            }}
          >
            {useRecoveryCode ? "Use an authenticator code instead" : "Use a recovery code instead"}
          </button>
        )}
        <button type="button" className="btn btn-link" onClick={() => onRestart()}>
          Start over
        </button>
      </div>
    </div>
  );
}

function RecoveryCodes({ codes, onContinue }: { codes: string[]; onContinue: () => void }) {
  const [copied, setCopied] = useState<"idle" | "copied" | "failed">("idle");

  async function copy() {
    try {
      await navigator.clipboard.writeText(codes.join("\n"));
      setCopied("copied");
    } catch {
      setCopied("failed");
    }
  }

  return (
    <div className="stack">
      <Notice>
        <strong>MFA is enabled.</strong> Save these recovery codes somewhere safe. Each one can be used once if you lose
        your authenticator. <strong>They will not be shown again.</strong>
      </Notice>
      <ul className="recovery-grid" aria-label="Recovery codes">
        {codes.map((c) => (
          <li key={c}>{c}</li>
        ))}
      </ul>
      <div className="button-row">
        <button type="button" className="btn" onClick={() => void copy()}>
          {copied === "copied" ? "Copied ✓" : "Copy codes"}
        </button>
        <button type="button" className="btn btn-primary" onClick={onContinue}>
          I saved them — continue
        </button>
      </div>
      {copied === "failed" ? <p className="muted small">Copy failed — please select and copy the codes manually.</p> : null}
    </div>
  );
}
