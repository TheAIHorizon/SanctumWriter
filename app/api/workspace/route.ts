import { NextResponse } from 'next/server';
import { readdir, stat } from 'fs/promises';
import { join, dirname, basename, resolve, sep } from 'path';
import { existsSync } from 'fs';
import { homedir } from 'os';

interface DirectoryEntry {
  name: string;
  path: string;
  type: 'file' | 'directory';
}

function isWithin(parent: string, child: string): boolean {
  return child === parent || child.startsWith(parent + sep);
}

// Security: reject any path containing a `..` segment (directory traversal),
// and confine browsing/validation to the user's home directory or the app
// directory - the areas a vault can legitimately live in.
function checkBrowsePath(rawPath: string): { ok: true; path: string } | { ok: false; status: number; error: string } {
  if (rawPath.split(/[\\/]+/).includes('..')) {
    return { ok: false, status: 400, error: 'Invalid path' };
  }
  const resolved = resolve(rawPath);
  const allowedRoots = [resolve(homedir()), resolve(process.cwd())];
  if (!allowedRoots.some((root) => isWithin(root, resolved))) {
    return { ok: false, status: 403, error: 'Path is outside the allowed area' };
  }
  return { ok: true, path: resolved };
}

// Get list of directories for folder browser
export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const requestedPath = searchParams.get('path') || homedir();

  const check = checkBrowsePath(requestedPath);
  if (!check.ok) {
    return NextResponse.json(
      { error: check.error, path: requestedPath },
      { status: check.status }
    );
  }
  const path = check.path;

  try {
    // Validate path exists
    if (!existsSync(path)) {
      return NextResponse.json(
        { error: 'Path does not exist', path },
        { status: 404 }
      );
    }
    
    const stats = await stat(path);
    if (!stats.isDirectory()) {
      return NextResponse.json(
        { error: 'Path is not a directory', path },
        { status: 400 }
      );
    }
    
    const items = await readdir(path);
    const entries: DirectoryEntry[] = [];
    
    for (const item of items) {
      // Skip hidden files/folders on Windows and Unix
      if (item.startsWith('.') || item.startsWith('$')) continue;
      
      try {
        const fullPath = join(path, item);
        const itemStats = await stat(fullPath);
        
        // Only include directories
        if (itemStats.isDirectory()) {
          entries.push({
            name: item,
            path: fullPath,
            type: 'directory',
          });
        }
      } catch {
        // Skip items we can't access
        continue;
      }
    }
    
    // Sort alphabetically
    entries.sort((a, b) => a.name.localeCompare(b.name));
    
    return NextResponse.json({
      currentPath: path,
      parentPath: dirname(path),
      entries,
      canGoUp: path !== dirname(path) && checkBrowsePath(dirname(path)).ok, // Can't go up past the allowed root
    });
  } catch (error) {
    console.error('Error browsing directory:', error);
    return NextResponse.json(
      { error: 'Failed to browse directory' },
      { status: 500 }
    );
  }
}

// Validate a workspace path
export async function POST(request: Request) {
  try {
    const { path: rawPath } = await request.json();

    if (!rawPath) {
      return NextResponse.json(
        { error: 'Path is required' },
        { status: 400 }
      );
    }

    const check = checkBrowsePath(rawPath);
    if (!check.ok) {
      return NextResponse.json(
        { error: check.error, path: rawPath },
        { status: check.status }
      );
    }
    const path = check.path;

    // Check if path exists
    if (!existsSync(path)) {
      return NextResponse.json({
        valid: false,
        error: 'Path does not exist',
        path,
      });
    }
    
    // Check if it's a directory
    const stats = await stat(path);
    if (!stats.isDirectory()) {
      return NextResponse.json({
        valid: false,
        error: 'Path is not a directory',
        path,
      });
    }
    
    // Count markdown files
    let markdownCount = 0;
    const countMarkdown = async (dir: string, depth = 0) => {
      if (depth > 3) return; // Don't go too deep
      
      try {
        const items = await readdir(dir);
        for (const item of items) {
          if (item.startsWith('.') || item === 'node_modules') continue;
          
          const fullPath = join(dir, item);
          try {
            const itemStats = await stat(fullPath);
            if (itemStats.isDirectory()) {
              await countMarkdown(fullPath, depth + 1);
            } else if (item.match(/\.(md|markdown|mdx|txt)$/i)) {
              markdownCount++;
            }
          } catch {
            continue;
          }
        }
      } catch {
        // Ignore errors
      }
    };
    
    await countMarkdown(path);
    
    return NextResponse.json({
      valid: true,
      path,
      name: basename(path),
      markdownFiles: markdownCount,
    });
  } catch (error) {
    console.error('Error validating workspace:', error);
    return NextResponse.json(
      { error: 'Failed to validate workspace' },
      { status: 500 }
    );
  }
}














