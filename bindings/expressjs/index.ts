import type { Request, Response, NextFunction } from 'express';
import { JsEGuard, JsEGuardConfig, JsDecision } from 'eguard';

export type EGuardOptions = JsEGuardConfig;

export function eGuardMiddleware(opts: EGuardOptions) {
  const guard = new JsEGuard(opts);
  const headerName = opts.sessionExtraction.headerName?.toLowerCase();

  return async function eGuard(req: Request, res: Response, next: NextFunction) {
    
    if (!guard.isSecure(req.path, req.method)) return next();

    const cookieHeader = req.headers['cookie'] as string | undefined;
    const headerVal =
      headerName && typeof req.headers[headerName] === 'string'
        ? (req.headers[headerName] as string)
        : undefined;

    const sid = guard.extractSessionId(
      cookieHeader ?? null,
      opts.sessionExtraction.headerName ?? null,
      headerVal ?? null
    );

    if (!sid) {
      return res.status(401).json({ error: 'missing_session' });
    }

    try {
      const decision = (await guard.decide(sid)) as JsDecision;
      if (decision.allow) return next();
      return res
        .status(decision.status ?? 403)
        .json({ error: 'forbidden', detail: decision.message });
    } catch {
      return res.status(502).json({ error: 'trust_service_unavailable' });
    }
  };
}
