# SecVal Frontend

Modern, minimal, and elegant web UI for SecVal vulnerability scanner built with React + Vite + TypeScript + Tailwind CSS.

## Features

- 🎯 **Clean Form** - Add/remove targets and select scan modules
- 📊 **Real-time Progress** - Live polling with percentage and module completion
- 📈 **Summary Stats** - Cards showing secure/warning/vulnerable/error counts
- 📋 **Detailed Results** - Expandable results grouped by module
- 💾 **Report Export** - Download scan results as XLSX
- 🎨 **Dark Theme** - Professional slate/blue color scheme
- 📱 **Responsive** - Works on mobile, tablet, desktop

## Quick Start

### Prerequisites
- Node.js 18+
- npm or yarn

### Install Dependencies
```bash
cd frontend
npm install
```

### Development Server
```bash
npm run dev
```
Starts at `http://localhost:3000` with proxy to backend at `http://localhost:8000`

### Build for Production
```bash
npm run build
```
Output in `dist/`

## Project Structure

```
frontend/
├── src/
│   ├── components/
│   │   ├── ScanForm.tsx           # Form for creating scans
│   │   ├── ProgressBar.tsx        # Progress indicator
│   │   └── ResultsTable.tsx       # Detailed results
│   ├── api/
│   │   └── client.ts              # Axios client
│   ├── types/
│   │   └── index.ts               # TypeScript types
│   ├── App.tsx                    # Main app component
│   ├── main.tsx                   # Entry point
│   └── index.css                  # Tailwind + custom styles
├── index.html                     # HTML template
├── vite.config.ts                 # Vite configuration
├── tsconfig.json                  # TypeScript config
├── tailwind.config.js             # Tailwind CSS config
└── package.json
```

## API Integration

Frontend communicates with backend API at `/api`:
- `POST /api/scans` - Create scan
- `GET /api/scans/{scanId}` - Get status (polled every 1s)
- `GET /api/scans/{scanId}/summary` - Get summary
- `GET /api/scans/{scanId}/report.xlsx` - Download report

Vite proxy in `vite.config.ts` forwards `/api/*` requests to `http://localhost:8000`.

## Styling

- **Framework**: Tailwind CSS
- **Icons**: lucide-react
- **Color Scheme**: Slate (950 dark) + Blue (600 primary)
- **Components**: Custom utility classes in `index.css`

## Type Safety

All components use TypeScript with strict mode enabled. Types match the OpenAPI contract.

## Running with Backend

### Terminal 1: Backend (FastAPI)
```bash
cd ..
uvicorn backend.app_fastapi:app --reload
# Runs on http://localhost:8000
```

### Terminal 2: Frontend (Vite)
```bash
cd frontend
npm run dev
# Runs on http://localhost:3000
```

Visit `http://localhost:3000` and start scanning!

## License

MIT
