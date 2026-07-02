/**
 * Server-side default service URLs.
 *
 * These run in Next.js API routes (no access to browser localStorage /
 * zustand persistence), so they're configured via environment variables
 * with the same localhost defaults the app has always shipped with.
 *
 * Client-side code should NOT import this file — it should read the
 * user's configured URLs from the settings store instead (see
 * lib/llm/client.ts's getOllamaUrl()/getLMStudioUrl()).
 */

export const OLLAMA_URL = process.env.OLLAMA_URL || 'http://localhost:11434';
export const LMSTUDIO_URL = process.env.LMSTUDIO_URL || 'http://localhost:1234';
