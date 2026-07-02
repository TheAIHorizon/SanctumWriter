import { NextResponse } from 'next/server';
import { readFile, writeFile, unlink, rename } from 'fs/promises';
import { join, dirname, basename, isAbsolute, resolve, sep } from 'path';
import { existsSync } from 'fs';
import { homedir } from 'os';

const DEFAULT_WORKSPACE_PATH = process.env.WORKSPACE_PATH || './documents';

// Error type for path confinement violations so handlers can return 400/403
// instead of a generic 500.
class PathAccessError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

function isWithin(parent: string, child: string): boolean {
  return child === parent || child.startsWith(parent + sep);
}

// Security: reject any path containing a `..` segment (directory traversal).
function hasTraversalSegment(value: string): boolean {
  return value.split(/[\\/]+/).includes('..');
}

// Resolve the workspace root. Custom workspace values must not contain `..`
// segments, and absolute workspaces must stay inside the user's home
// directory or the app directory (the areas a vault can legitimately live in).
function getWorkspacePath(customPath?: string): string {
  const defaultRoot = resolve(process.cwd(), DEFAULT_WORKSPACE_PATH);
  if (!customPath) {
    return defaultRoot;
  }
  if (hasTraversalSegment(customPath)) {
    throw new PathAccessError('Invalid workspace path', 400);
  }
  const resolved = isAbsolute(customPath)
    ? resolve(customPath)
    : resolve(process.cwd(), customPath);
  const allowedRoots = [resolve(process.cwd()), resolve(homedir()), defaultRoot];
  if (!allowedRoots.some((root) => isWithin(root, resolved))) {
    throw new PathAccessError('Workspace path is outside the allowed area', 403);
  }
  return resolved;
}

// Resolve a path inside the workspace, rejecting anything that escapes it.
function getFullPath(pathSegments: string[], workspace?: string): string {
  const root = getWorkspacePath(workspace);
  const relativePath = pathSegments.join('/');
  if (hasTraversalSegment(relativePath) || isAbsolute(relativePath)) {
    throw new PathAccessError('Invalid path', 400);
  }
  const fullPath = resolve(root, relativePath);
  if (!isWithin(root, fullPath) || fullPath === root) {
    throw new PathAccessError('Path is outside the workspace', 403);
  }
  return fullPath;
}

function pathErrorResponse(error: unknown): NextResponse | null {
  if (error instanceof PathAccessError) {
    return NextResponse.json({ error: error.message }, { status: error.status });
  }
  return null;
}

export async function GET(
  request: Request,
  { params }: { params: { path: string[] } }
) {
  try {
    const { searchParams } = new URL(request.url);
    const workspace = searchParams.get('workspace') || undefined;
    const filePath = getFullPath(params.path, workspace);

    if (!existsSync(filePath)) {
      return NextResponse.json(
        { error: 'File not found' },
        { status: 404 }
      );
    }

    const content = await readFile(filePath, 'utf-8');
    const path = params.path.join('/');

    return NextResponse.json({
      content,
      path,
      name: basename(filePath),
    });
  } catch (error) {
    const denied = pathErrorResponse(error);
    if (denied) return denied;
    console.error('Error reading file:', error);
    return NextResponse.json(
      { error: 'Failed to read file' },
      { status: 500 }
    );
  }
}

export async function PUT(
  request: Request,
  { params }: { params: { path: string[] } }
) {
  try {
    const { content, workspace } = await request.json();
    const filePath = getFullPath(params.path, workspace);

    // Ensure the directory exists
    const { mkdir } = await import('fs/promises');
    await mkdir(dirname(filePath), { recursive: true });

    await writeFile(filePath, content, 'utf-8');

    return NextResponse.json({
      success: true,
      path: params.path.join('/'),
    });
  } catch (error) {
    const denied = pathErrorResponse(error);
    if (denied) return denied;
    console.error('Error saving file:', error);
    return NextResponse.json(
      { error: 'Failed to save file' },
      { status: 500 }
    );
  }
}

export async function DELETE(
  request: Request,
  { params }: { params: { path: string[] } }
) {
  try {
    const { searchParams } = new URL(request.url);
    const workspace = searchParams.get('workspace') || undefined;
    const filePath = getFullPath(params.path, workspace);

    if (!existsSync(filePath)) {
      return NextResponse.json(
        { error: 'File not found' },
        { status: 404 }
      );
    }

    await unlink(filePath);

    return NextResponse.json({
      success: true,
      path: params.path.join('/'),
    });
  } catch (error) {
    const denied = pathErrorResponse(error);
    if (denied) return denied;
    console.error('Error deleting file:', error);
    return NextResponse.json(
      { error: 'Failed to delete file' },
      { status: 500 }
    );
  }
}

export async function PATCH(
  request: Request,
  { params }: { params: { path: string[] } }
) {
  try {
    const { newName, destinationPath, workspace } = await request.json();
    const oldPath = getFullPath(params.path, workspace);
    const workspaceRoot = getWorkspacePath(workspace);

    if (!existsSync(oldPath)) {
      return NextResponse.json(
        { error: 'File not found' },
        { status: 404 }
      );
    }

    let newPath: string;
    let newRelativePath: string[];

    // If destinationPath is provided, this is a move operation
    if (destinationPath !== undefined) {
      // destinationPath is relative to workspace - empty string means root
      if (
        typeof destinationPath === 'string' &&
        (hasTraversalSegment(destinationPath) || isAbsolute(destinationPath))
      ) {
        return NextResponse.json(
          { error: 'Invalid destination path' },
          { status: 400 }
        );
      }

      const { mkdir } = await import('fs/promises');
      const fileName = basename(oldPath);

      const destDir = destinationPath
        ? join(workspaceRoot, destinationPath)
        : workspaceRoot;

      if (!isWithin(workspaceRoot, resolve(destDir))) {
        return NextResponse.json(
          { error: 'Destination is outside the workspace' },
          { status: 403 }
        );
      }

      // Ensure destination directory exists
      await mkdir(destDir, { recursive: true });

      newPath = join(destDir, fileName);
      newRelativePath = destinationPath
        ? [...destinationPath.split('/').filter(Boolean), fileName]
        : [fileName];

      // Check if source and destination are the same
      if (oldPath === newPath) {
        return NextResponse.json({
          success: true,
          oldPath: params.path.join('/'),
          newPath: newRelativePath.join('/'),
          message: 'File is already in this location'
        });
      }
    } else if (newName) {
      // This is a rename operation (existing behavior)
      newPath = join(dirname(oldPath), newName);
      // The new name must stay in the same directory (no separators or `..`)
      if (
        hasTraversalSegment(newName) ||
        isAbsolute(newName) ||
        resolve(newPath) !== newPath ||
        !isWithin(workspaceRoot, resolve(newPath))
      ) {
        return NextResponse.json(
          { error: 'Invalid file name' },
          { status: 400 }
        );
      }
      const pathParts = [...params.path];
      pathParts[pathParts.length - 1] = newName;
      newRelativePath = pathParts;
    } else {
      return NextResponse.json(
        { error: 'Must provide either newName or destinationPath' },
        { status: 400 }
      );
    }

    if (existsSync(newPath)) {
      return NextResponse.json(
        { error: 'A file with that name already exists in the destination' },
        { status: 409 }
      );
    }

    await rename(oldPath, newPath);

    return NextResponse.json({
      success: true,
      oldPath: params.path.join('/'),
      newPath: newRelativePath.join('/'),
    });
  } catch (error) {
    const denied = pathErrorResponse(error);
    if (denied) return denied;
    console.error('Error moving/renaming file:', error);
    return NextResponse.json(
      { error: 'Failed to move/rename file' },
      { status: 500 }
    );
  }
}
