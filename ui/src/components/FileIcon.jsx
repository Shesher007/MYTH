import {
    FileText, Code, Image as ImageIcon, Music,
    Video, FolderArchive, Shield, Database, Table,
    Terminal, BookOpen, File, Folder,
    Activity, Cpu, Globe, Boxes, RotateCcw,
    Layers, PenTool, ClipboardList, FileWarning,
    Type, Key, Disc, Bug, Fingerprint, Search, Info,
    Smartphone, FlaskConical, Component,
    Brain, Coins, Cloud, Book
} from 'lucide-react';

export const getFileIconDetails = (name, type) => {
    const extMatch = name?.match(/\.([a-z0-9]+)$/i);
    const ext = extMatch ? extMatch[1].toLowerCase() : (type?.startsWith('.') ? type.slice(1).toLowerCase() : null);
    const mime = type?.toLowerCase();
    const lowerName = name?.toLowerCase() || "";

    // 1. Directories & Special Types
    if (type === 'folder' || ext === 'dir') return { Icon: Folder, color: 'text-teal-500', label: 'DIR' };
    if (type === 'internet_asset' || lowerName.startsWith('http') || mime?.includes('url')) {
        return { Icon: Globe, color: 'text-cyan-400', label: 'REMOTE_INTEL' };
    }

    // 2. Security & Forensics
    if (['hash', 'sig', 'md5', 'sha', 'sha1', 'sha256', 'sha512', 'sum', 'crc'].includes(ext)) {
        return { Icon: Fingerprint, color: 'text-amber-400', label: 'CHECKSUM' };
    }
    if (['pem', 'key', 'crt', 'cer', 'ssh', 'pub', 'gpg', 'asc', 'auth', 'cert', 'pfx', 'p12'].includes(ext)) {
        return { Icon: Key, color: 'text-slate-300', label: 'SECURITY_KEY' };
    }
    if (['malware', 'suspicious', 'vdetect', 'virus', 'threat', 'infected'].includes(ext) || lowerName.includes('virus')) {
        return { Icon: Bug, color: 'text-red-600', label: 'THREAT_MATCH' };
    }
    if (['pcap', 'cap', 'pcapng', 'har', 'snoop', 'nfs'].includes(ext)) {
        return { Icon: Activity, color: 'text-cyan-500', label: 'NET_CAPTURE' };
    }
    if (['results', 'matches', 'findings', 'grep'].includes(ext)) {
        return { Icon: Search, color: 'text-blue-300', label: 'FINDINGS' };
    }

    // 3. Binaries & Executables
    if (['exe', 'msi', 'bin', 'dll', 'so', 'o', 'elf', 'sys', 'drv', 'com', 'vxd', 'lib', 'a'].includes(ext)) {
        return { Icon: Shield, color: 'text-red-500', label: 'BINARY' };
    }

    // 4. Source Code & Scripts
    if (['py', 'js', 'jsx', 'ts', 'tsx', 'cpp', 'h', 'cs', 'go', 'rs', 'php', 'rb', 'java', 'lua', 'c', 'cc', 'm', 'mm', 'swift', 'kt', 'gradle', 'dart', 'scala'].includes(ext)) {
        return { Icon: Code, color: 'text-teal-400', label: 'SOURCE' };
    }
    if (['sh', 'bat', 'ps1', 'cmd', 'bash', 'vbs', 'scr'].includes(ext) || lowerName === 'dockerfile' || lowerName === 'makefile') {
        return { Icon: Terminal, color: 'text-orange-500', label: 'SCRIPT' };
    }

    // 5. Data & Database
    if (['sqlite', 'db', 'sql', 'mdb', 'accdb', 'parquet', 'avro', 'dat', 'dbf'].includes(ext)) {
        return { Icon: Database, color: 'text-blue-500', label: 'DATABASE' };
    }
    if (['json', 'yaml', 'yml', 'toml', 'xml', 'conf', 'ini', 'props', 'config', 'settings', 'env'].includes(ext)) {
        return { Icon: Database, color: 'text-amber-500', label: 'CONFIG' };
    }
    if (['csv', 'xls', 'xlsx', 'ods', 'tsv'].includes(ext)) {
        return { Icon: Table, color: 'text-emerald-500', label: 'SPREADSHEET' };
    }

    // 6. Media - Image/Audio/Video
    if (['png', 'jpg', 'jpeg', 'gif', 'webp', 'svg', 'ico', 'bmp', 'tiff', 'heif', 'jfif', 'avif', 'apng', 'pjpeg', 'pjp'].includes(ext) || mime?.startsWith('image/')) {
        return { Icon: ImageIcon, color: 'text-purple-400', label: 'IMAGE' };
    }
    if (['mp3', 'wav', 'ogg', 'flac', 'm4a', 'aac', 'wma', 'opus'].includes(ext) || mime?.startsWith('audio/')) {
        return { Icon: Music, color: 'text-pink-400', label: 'AUDIO' };
    }
    if (['mp4', 'mkv', 'avi', 'mov', 'webm', 'flv', 'wmv'].includes(ext) || mime?.startsWith('video/')) {
        return { Icon: Video, color: 'text-rose-400', label: 'VIDEO' };
    }

    // 7. Archives
    if (['zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz', 'lz', 'zst', 'pkg', 'deb', 'rpm'].includes(ext)) {
        return { Icon: FolderArchive, color: 'text-yellow-600', label: 'ARCHIVE' };
    }

    // 8. Visual & 3D
    if (['obj', 'fbx', 'stl', 'glb', 'gltf', '3ds', 'max', 'blend'].includes(ext)) {
        return { Icon: Boxes, color: 'text-indigo-400', label: '3D_MODEL' };
    }
    if (['psd', 'ai', 'sketch', 'fig', 'eps'].includes(ext)) {
        return { Icon: PenTool, color: 'text-blue-400', label: 'DESIGN' };
    }
    if (['ttf', 'otf', 'woff', 'woff2', 'eot', 'fnt'].includes(ext)) {
        return { Icon: Type, color: 'text-slate-400', label: 'FONT' };
    }

    // 9. Virtualization & Disks
    if (['vmdk', 'vhd', 'qcow2', 'vdi', 'ova', 'ovf'].includes(ext)) {
        return { Icon: Layers, color: 'text-slate-500', label: 'VIRTUAL_DISK' };
    }
    if (['iso', 'img', 'dmg', 'vcd'].includes(ext)) {
        return { Icon: Disc, color: 'text-slate-300', label: 'DISK_IMAGE' };
    }

    // 10. Documents & Info
    if (['pdf'].includes(ext)) {
        return { Icon: FileText, color: 'text-red-400', label: 'PDF' };
    }
    if (['md', 'txt', 'rtf'].includes(ext) || lowerName === 'readme' || lowerName === 'license') {
        return { Icon: BookOpen, color: 'text-indigo-400', label: 'DOCS' };
    }
    if (['log', 'err', 'out', 'stats', 'diag', 'event', 'history'].includes(ext) || lowerName.includes('log')) {
        return { Icon: Info, color: 'text-slate-400', label: 'SYSTEM_LOG' };
    }

    // 11. Specialized
    if (['hex', 'rom', 'firmware', 'bios', 'dsn', 'sch', 'brd'].includes(ext)) {
        return { Icon: Cpu, color: 'text-cyan-500', label: 'FIRMWARE' };
    }
    if (['bak', 'backup', 'tmp', 'old', 'swp', 'part'].includes(ext)) {
        return { Icon: RotateCcw, color: 'text-slate-600', label: 'REDUNDANT' };
    }
    if (['manifest', 'jsonld', 'lock', 'yarn-lock', 'package-lock'].includes(ext) || lowerName.includes('manifest')) {
        return { Icon: ClipboardList, color: 'text-slate-400', label: 'MANIFEST' };
    }
    if (['error', 'fault', 'crash', 'panic'].includes(ext)) {
        return { Icon: FileWarning, color: 'text-red-500', label: 'FAULT' };
    }

    // 12. Mobile & Apps
    if (['apk', 'ipa', 'dex', 'appxbundle', 'xap'].includes(ext)) {
        return { Icon: Smartphone, color: 'text-emerald-400', label: 'MOBILE_APP' };
    }

    // 13. Scientific & Data
    if (['h5', 'fits', 'nc', 'mat', 'data', 'datasets'].includes(ext)) {
        return { Icon: FlaskConical, color: 'text-indigo-500', label: 'SCIENTIFIC' };
    }

    // 14. Engineering & CAD
    if (['dwg', 'dxf', 'step', 'stl'].includes(ext)) {
        return { Icon: Component, color: 'text-rose-500', label: 'ENGINEERING' };
    }

    // 15. AI & Machine Learning
    if (['safetensors', 'ckpt', 'onnx', 'pth', 'gguf', 'weights', 'model', 'onnx'].includes(ext) || lowerName.includes('model')) {
        return { Icon: Brain, color: 'text-amber-400', label: 'AI_MODEL' };
    }

    // 16. Crypto & Blockchain
    if (['wallet', 'ledger', 'blockchain', 'sol', 'eth'].includes(ext)) {
        return { Icon: Coins, color: 'text-yellow-500', label: 'CRYPTO' };
    }

    // 17. Cloud & Infrastructure
    if (['tf', 'hcl', 'tfvars', 'terraform', 'k8s', 'helm', 'nomad'].includes(ext)) {
        return { Icon: Cloud, color: 'text-blue-400', label: 'INFRA' };
    }

    // 18. E-Books
    if (['epub', 'mobi', 'azw3', 'fb2'].includes(ext)) {
        return { Icon: Book, color: 'text-lime-500', label: 'EBOOK' };
    }

    // Default Fallback
    return { Icon: File, color: 'text-slate-500', label: ext?.toUpperCase() || (type === 'internet_asset' ? 'REMOTE' : 'FILE') };
};

const FileIcon = ({ name, type, size = 16, className = "" }) => {
    const { Icon, color } = getFileIconDetails(name, type);
    return <Icon size={size} className={`${color} ${className}`} />;
};

export default FileIcon;