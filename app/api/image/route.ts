import { NextResponse } from 'next/server';
import { writeFile, mkdir } from 'fs/promises';
import { join, isAbsolute } from 'path';
import { existsSync } from 'fs';
import { assertSafeExternalUrl, UnsafeUrlError } from '@/lib/security/ssrfGuard';

const DEFAULT_COMFYUI_URL = 'http://127.0.0.1:8188';
const DEFAULT_WORKSPACE_PATH = process.env.WORKSPACE_PATH || './documents';

/**
 * POST /api/image
 * Queue an image generation in ComfyUI
 */
export async function POST(request: Request) {
  try {
    const { prompt, comfyuiUrl = DEFAULT_COMFYUI_URL } = await request.json();
    
    if (!prompt) {
      return NextResponse.json(
        { error: 'Prompt object is required' },
        { status: 400 }
      );
    }

    // Queue the prompt in ComfyUI
    const response = await fetch(`${comfyuiUrl}/prompt`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ prompt }),
    });

    if (!response.ok) {
      const error = await response.text();
      console.error('ComfyUI error:', error);
      return NextResponse.json(
        { error: `ComfyUI error: ${error}` },
        { status: response.status }
      );
    }

    const data = await response.json();
    
    return NextResponse.json({
      success: true,
      prompt_id: data.prompt_id,
      number: data.number,
    });
  } catch (error) {
    console.error('Failed to queue image generation:', error);
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to queue image generation' },
      { status: 500 }
    );
  }
}

/**
 * PUT /api/image
 * Save a generated image to the workspace
 */
export async function PUT(request: Request) {
  try {
    const {
      imageUrl,
      filename,
      outputFolder = './images/generated',
      workspace = DEFAULT_WORKSPACE_PATH,
      comfyuiUrl = DEFAULT_COMFYUI_URL,
    } = await request.json();

    if (!imageUrl || !filename) {
      return NextResponse.json(
        { error: 'imageUrl and filename are required' },
        { status: 400 }
      );
    }

    // SSRF guard: imageUrl is attacker-controllable (client-supplied JSON
    // body). Only fetch it if it's a public http(s) address, OR it matches
    // the user's configured ComfyUI origin (the one legitimate loopback
    // target for this endpoint - ComfyUI is expected to run locally). This
    // blocks redirecting the fetch to unrelated internal services (e.g.
    // cloud metadata at 169.254.169.254, or another local port) while still
    // allowing the normal "save the image ComfyUI just generated" flow.
    let trustedComfyOrigin: string | null = null;
    try {
      trustedComfyOrigin = new URL(comfyuiUrl).origin;
    } catch {
      // Malformed comfyuiUrl - fall through with no trusted origin, so the
      // generic private/loopback rejection below applies.
    }

    try {
      await assertSafeExternalUrl(imageUrl, {
        trustedOrigins: trustedComfyOrigin ? [trustedComfyOrigin] : [],
      });
    } catch (err) {
      if (err instanceof UnsafeUrlError) {
        return NextResponse.json({ error: err.message }, { status: 400 });
      }
      throw err;
    }

    // Fetch the image from ComfyUI
    const imageResponse = await fetch(imageUrl);
    if (!imageResponse.ok) {
      return NextResponse.json(
        { error: 'Failed to fetch image from ComfyUI' },
        { status: 500 }
      );
    }

    const imageBuffer = await imageResponse.arrayBuffer();

    // Determine the full path
    let basePath: string;
    if (isAbsolute(workspace)) {
      basePath = workspace;
    } else {
      basePath = join(process.cwd(), workspace);
    }

    const outputDir = join(basePath, outputFolder);
    const filePath = join(outputDir, filename);

    // Ensure output directory exists
    if (!existsSync(outputDir)) {
      await mkdir(outputDir, { recursive: true });
    }

    // Write the image file
    await writeFile(filePath, Buffer.from(imageBuffer));

    // Return the relative path for markdown insertion
    const relativePath = join(outputFolder, filename).replace(/\\/g, '/');

    return NextResponse.json({
      success: true,
      filename,
      relativePath,
      fullPath: filePath,
    });
  } catch (error) {
    console.error('Failed to save image:', error);
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to save image' },
      { status: 500 }
    );
  }
}

