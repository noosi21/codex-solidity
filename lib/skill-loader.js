const fs = require('fs');
const path = require('path');

class SkillLoader {
  constructor() {
    this.skillsDir = path.join(__dirname, '..', 'skills');
    this._cache = null;
  }

  _load() {
    if (this._cache) return this._cache;
    this._cache = [];
    const dirs = fs.readdirSync(this.skillsDir, { withFileTypes: true })
      .filter(d => d.isDirectory());
    for (const dir of dirs) {
      const skillPath = path.join(this.skillsDir, dir.name, 'index.js');
      if (fs.existsSync(skillPath)) {
        try {
          const skill = require(skillPath);
          if (skill.name && typeof skill.execute === 'function') {
            this._cache.push(skill);
          }
        } catch (err) {
          console.error(`Failed to load skill ${dir.name}: ${err.message}`);
        }
      }
    }
    return this._cache;
  }

  getAllSkills() { return this._load(); }
  getSkill(name) { return this._load().find(s => s.name === name || s.aliases?.includes(name)); }
  listSkills() { return this._load().map(s => s.name); }
}

module.exports = SkillLoader;
