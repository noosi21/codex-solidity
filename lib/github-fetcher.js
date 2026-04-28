/**
 * GitHub Repo Fetcher — Downloads smart contract source from GitHub URLs
 * Supports: full repo clone, subdirectory, single file, raw GitHub URLs
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const axios = require('axios');

class GitHubFetcher {
  constructor(opts = {}) {
    this.tmpDir = opts.tmpDir || '/tmp/codex-sol-contracts';
    this.clean = opts.clean !== false;
  }

  /**
   * Fetch contracts from a GitHub URL.
   * Supports:
   *   - https://github.com/org/repo
   *   - https://github.com/org/repo/tree/main/contracts
   *   - https://github.com/org/repo/blob/main/file.sol
   *   - https://raw.githubusercontent.com/org/repo/main/file.sol
   */
  async fetch(url) {
    const parsed = this._parseUrl(url);
    if (!parsed) throw new Error(`Invalid GitHub URL: ${url}`);

    // Clean previous fetch
    if (this.clean && fs.existsSync(this.tmpDir)) {
      try { fs.rmSync(this.tmpDir, { recursive: true }); } catch {}
    }
    fs.mkdirSync(this.tmpDir, { recursive: true });

    if (parsed.type === 'raw') {
      return this._fetchRaw(parsed);
    } else if (parsed.type === 'file') {
      return this._fetchSingleFile(parsed);
    } else if (parsed.type === 'tree') {
      return this._fetchSubdirectory(parsed);
    } else {
      return this._fetchRepo(parsed);
    }
  }

  _parseUrl(url) {
    // Raw GitHub
    const rawMatch = url.match(/raw\.githubusercontent\.com\/([^/]+)\/([^/]+)\/([^/]+)\/(.+)/);
    if (rawMatch) {
      return { type: 'raw', org: rawMatch[1], repo: rawMatch[2], branch: rawMatch[3], filepath: rawMatch[4] };
    }

    // GitHub blob (single file)
    const blobMatch = url.match(/github\.com\/([^/]+)\/([^/]+)\/blob\/([^/]+)\/(.+\.sol)/);
    if (blobMatch) {
      return { type: 'file', org: blobMatch[1], repo: blobMatch[2], branch: blobMatch[3], filepath: blobMatch[4] };
    }

    // GitHub tree (subdirectory)
    const treeMatch = url.match(/github\.com\/([^/]+)\/([^/]+)\/tree\/([^/]+)\/(.+)/);
    if (treeMatch) {
      return { type: 'tree', org: treeMatch[1], repo: treeMatch[2], branch: treeMatch[3], subdir: treeMatch[4] };
    }

    // GitHub repo root
    const repoMatch = url.match(/github\.com\/([^/]+)\/([^/]+)(?:\.git)?\/?$/);
    if (repoMatch) {
      return { type: 'repo', org: repoMatch[1], repo: repoMatch[2] };
    }

    // GitHub repo with trailing path or .git
    const repoMatch2 = url.match(/github\.com\/([^/]+)\/([^/]+)/);
    if (repoMatch2) {
      return { type: 'repo', org: repoMatch2[1], repo: repoMatch2[2] };
    }

    return null;
  }

  async _fetchRepo(parsed) {
    const cloneUrl = `https://github.com/${parsed.org}/${parsed.repo}.git`;
    const targetDir = path.join(this.tmpDir, parsed.repo);

    console.log(`  Cloning ${parsed.org}/${parsed.repo}...`);
    try {
      execSync(`git clone --depth 1 ${cloneUrl} ${targetDir}`, { stdio: 'pipe', timeout: 60000 });
    } catch (err) {
      // Fallback: download zip
      return this._fetchZip(parsed);
    }

    const solFiles = this._findSolFiles(targetDir);
    if (solFiles.length === 0) {
      console.log('  No .sol files found in repo root, searching subdirectories...');
    }

    return {
      localPath: targetDir,
      repo: `${parsed.org}/${parsed.repo}`,
      files: solFiles,
      type: 'repo',
    };
  }

  async _fetchSubdirectory(parsed) {
    const cloneUrl = `https://github.com/${parsed.org}/${parsed.repo}.git`;
    const targetDir = path.join(this.tmpDir, parsed.repo);

    console.log(`  Cloning ${parsed.org}/${parsed.repo} (sparse: ${parsed.subdir})...`);
    try {
      execSync(`git clone --depth 1 --sparse ${cloneUrl} ${targetDir}`, { stdio: 'pipe', timeout: 60000 });
      execSync(`git -C ${targetDir} sparse-checkout set ${parsed.subdir}`, { stdio: 'pipe', timeout: 30000 });
    } catch (err) {
      return this._fetchZip(parsed);
    }

    const subDir = path.join(targetDir, parsed.subdir);
    const solFiles = this._findSolFiles(subDir);

    return {
      localPath: subDir,
      repo: `${parsed.org}/${parsed.repo}`,
      subdir: parsed.subdir,
      files: solFiles,
      type: 'subdirectory',
    };
  }

  async _fetchSingleFile(parsed) {
    const rawUrl = `https://raw.githubusercontent.com/${parsed.org}/${parsed.repo}/${parsed.branch}/${parsed.filepath}`;
    const fileName = path.basename(parsed.filepath);
    const targetPath = path.join(this.tmpDir, fileName);

    console.log(`  Downloading ${parsed.filepath}...`);
    const resp = await axios.get(rawUrl, { responseType: 'text' });
    fs.writeFileSync(targetPath, resp.data);

    return {
      localPath: this.tmpDir,
      repo: `${parsed.org}/${parsed.repo}`,
      file: fileName,
      files: [targetPath],
      type: 'file',
    };
  }

  async _fetchRaw(parsed) {
    const rawUrl = `https://raw.githubusercontent.com/${parsed.org}/${parsed.repo}/${parsed.branch}/${parsed.filepath}`;
    const fileName = path.basename(parsed.filepath);
    const targetPath = path.join(this.tmpDir, fileName);

    console.log(`  Downloading ${parsed.filepath}...`);
    const resp = await axios.get(rawUrl, { responseType: 'text' });
    fs.writeFileSync(targetPath, resp.data);

    return {
      localPath: this.tmpDir,
      repo: `${parsed.org}/${parsed.repo}`,
      file: fileName,
      files: [targetPath],
      type: 'file',
    };
  }

  async _fetchZip(parsed) {
    const zipUrl = `https://github.com/${parsed.org}/${parsed.repo}/archive/refs/heads/main.zip`;
    const zipPath = path.join(this.tmpDir, `${parsed.repo}.zip`);
    const extractDir = path.join(this.tmpDir, parsed.repo);

    console.log(`  Downloading ZIP archive...`);
    try {
      const resp = await axios.get(zipUrl, { responseType: 'arraybuffer' });
      fs.writeFileSync(zipPath, resp.data);

      // Try unzip
      try {
        execSync(`unzip -q -o ${zipPath} -d ${this.tmpDir}`, { stdio: 'pipe', timeout: 30000 });
      } catch {
        // Try powershell on Windows
        try {
          execSync(`powershell -c "Expand-Archive -Path '${zipPath}' -DestinationPath '${this.tmpDir}' -Force"`, { stdio: 'pipe', timeout: 30000 });
        } catch {
          throw new Error('Cannot extract ZIP — install unzip or use git clone');
        }
      }

      // Find extracted directory (usually repo-main)
      const entries = fs.readdirSync(this.tmpDir).filter(e => e.startsWith(parsed.repo));
      const extractedDir = entries.find(e => fs.statSync(path.join(this.tmpDir, e)).isDirectory());
      if (!extractedDir) throw new Error('ZIP extraction failed');

      const solFiles = this._findSolFiles(path.join(this.tmpDir, extractedDir));
      return {
        localPath: path.join(this.tmpDir, extractedDir),
        repo: `${parsed.org}/${parsed.repo}`,
        files: solFiles,
        type: 'repo',
      };
    } catch (err) {
      throw new Error(`Failed to fetch repo: ${err.message}`);
    }
  }

  _findSolFiles(dir) {
    const files = [];
    const walk = (d) => {
      try {
        const entries = fs.readdirSync(d, { withFileTypes: true });
        for (const entry of entries) {
          if (entry.name.startsWith('.') || entry.name === 'node_modules' || entry.name === 'lib') continue;
          const fullPath = path.join(d, entry.name);
          if (entry.isDirectory()) walk(fullPath);
          else if (entry.name.endsWith('.sol')) files.push(fullPath);
        }
      } catch {}
    };
    walk(dir);
    return files;
  }

  cleanup() {
    if (fs.existsSync(this.tmpDir)) {
      try { fs.rmSync(this.tmpDir, { recursive: true }); } catch {}
    }
  }
}

module.exports = GitHubFetcher;
