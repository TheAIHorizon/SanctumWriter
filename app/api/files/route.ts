import { NextResponse } from 'next/server';
import { readdir, stat, mkdir } from 'fs/promises';
import { join, relative, isAbsolute, resolve, sep } from 'path';
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

function pathErrorResponse(error: unknown): NextResponse | null {
  if (error instanceof PathAccessError) {
    return NextResponse.json({ error: error.message }, { status: error.status });
  }
  return null;
}

interface FileNode {
  name: string;
  path: string;
  type: 'file' | 'directory';
  children?: FileNode[];
}

async function getFileTree(dirPath: string, basePath: string): Promise<FileNode[]> {
  const items = await readdir(dirPath);
  const nodes: FileNode[] = [];

  for (const item of items) {
    // Skip hidden files and common non-document files
    if (item.startsWith('.') || item === 'node_modules') continue;

    const fullPath = join(dirPath, item);
    const relativePath = relative(basePath, fullPath);
    const stats = await stat(fullPath);

    if (stats.isDirectory()) {
      const children = await getFileTree(fullPath, basePath);
      nodes.push({
        name: item,
        path: relativePath.replace(/\\/g, '/'),
        type: 'directory',
        children,
      });
    } else {
      // Only include markdown and text files
      const ext = item.split('.').pop()?.toLowerCase();
      if (['md', 'markdown', 'mdx', 'txt'].includes(ext || '')) {
        nodes.push({
          name: item,
          path: relativePath.replace(/\\/g, '/'),
          type: 'file',
        });
      }
    }
  }

  // Sort: directories first, then files, alphabetically
  return nodes.sort((a, b) => {
    if (a.type !== b.type) return a.type === 'directory' ? -1 : 1;
    return a.name.localeCompare(b.name);
  });
}

export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const customWorkspace = searchParams.get('workspace');
    const workspacePath = getWorkspacePath(customWorkspace || undefined);
    
    // Create workspace directory if it doesn't exist
    if (!existsSync(workspacePath)) {
      await mkdir(workspacePath, { recursive: true });
    }

    const files = await getFileTree(workspacePath, workspacePath);
    
    return NextResponse.json({ files, workspacePath });
  } catch (error) {
    const denied = pathErrorResponse(error);
    if (denied) return denied;
    console.error('Error reading files:', error);
    return NextResponse.json(
      { error: 'Failed to read files' },
      { status: 500 }
    );
  }
}

export async function POST(request: Request) {
  try {
    const { name, parentPath, workspace, type = 'file' } = await request.json();
    
    if (!name) {
      return NextResponse.json(
        { error: 'Name is required' },
        { status: 400 }
      );
    }

    const workspacePath = getWorkspacePath(workspace);

    // Security: keep the new file/folder inside the workspace
    if (
      hasTraversalSegment(name) ||
      isAbsolute(name) ||
      (parentPath && (hasTraversalSegment(parentPath) || isAbsolute(parentPath)))
    ) {
      return NextResponse.json(
        { error: 'Invalid path' },
        { status: 400 }
      );
    }

    const targetPath = parentPath
      ? join(workspacePath, parentPath, name)
      : join(workspacePath, name);

    if (!isWithin(workspacePath, resolve(targetPath))) {
      return NextResponse.json(
        { error: 'Path is outside the workspace' },
        { status: 403 }
      );
    }

    // Check if already exists
    if (existsSync(targetPath)) {
      return NextResponse.json(
        { error: `${type === 'folder' ? 'Folder' : 'File'} already exists` },
        { status: 409 }
      );
    }

    const relativePath = relative(workspacePath, targetPath).replace(/\\/g, '/');

    if (type === 'folder') {
      // Create folder
      await mkdir(targetPath, { recursive: true });
      
      return NextResponse.json({
        success: true,
        path: relativePath,
        name,
        type: 'folder',
      });
    } else {
      // Create file with default content
      const { writeFile } = await import('fs/promises');
      const defaultContent = `# ${name.replace(/\.(md|markdown|mdx)$/i, '')}\n\nStart writing here...\n`;
      await writeFile(targetPath, defaultContent, 'utf-8');
      
      return NextResponse.json({
        success: true,
        path: relativePath,
        name,
        content: defaultContent,
        type: 'file',
      });
    }
  } catch (error) {
    const denied = pathErrorResponse(error);
    if (denied) return denied;
    console.error('Error creating:', error);
    return NextResponse.json(
      { error: 'Failed to create' },
      { status: 500 }
    );
  }
}

