const fs = require('node:fs/promises');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const publicDir = path.join(root, 'public');
const interSource = path.join(root, 'node_modules', '@fontsource', 'inter', 'files');
const fontAwesomeSource = path.join(root, 'node_modules', '@fortawesome', 'fontawesome-free');
const interDestination = path.join(publicDir, 'fonts');
const fontAwesomeDestination = path.join(publicDir, 'vendor', 'fontawesome');

async function copyInterFonts() {
    await fs.mkdir(interDestination, { recursive: true });
    for (const weight of [300, 400, 500, 600, 700]) {
        const fileName = `inter-latin-${weight}-normal.woff2`;
        await fs.copyFile(path.join(interSource, fileName), path.join(interDestination, fileName));
    }
}

async function copyFontAwesome() {
    const cssDestination = path.join(fontAwesomeDestination, 'css');
    const webFontsDestination = path.join(fontAwesomeDestination, 'webfonts');
    await Promise.all([
        fs.mkdir(cssDestination, { recursive: true }),
        fs.mkdir(webFontsDestination, { recursive: true })
    ]);

    await fs.copyFile(
        path.join(fontAwesomeSource, 'css', 'all.min.css'),
        path.join(cssDestination, 'all.min.css')
    );

    for (const entry of await fs.readdir(path.join(fontAwesomeSource, 'webfonts'), { withFileTypes: true })) {
        if (entry.isFile()) {
            await fs.copyFile(
                path.join(fontAwesomeSource, 'webfonts', entry.name),
                path.join(webFontsDestination, entry.name)
            );
        }
    }
}

async function main() {
    await Promise.all([copyInterFonts(), copyFontAwesome()]);
}

main().catch(error => {
    console.error('Unable to copy local font assets:', error);
    process.exitCode = 1;
});
