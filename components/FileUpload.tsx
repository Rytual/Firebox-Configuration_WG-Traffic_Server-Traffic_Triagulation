import React from 'react';

interface FileUploadProps {
  label: string;
  accept: string;
  onFileSelect: (content: string, fileName: string) => void;
  color?: string;
}

export const FileUpload: React.FC<FileUploadProps> = ({ label, accept, onFileSelect, color = "cyan" }) => {
  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const text = event.target?.result as string;
      onFileSelect(text, file.name);
    };
    reader.readAsText(file);
  };

  return (
    <div className={`border border-slate-700 bg-slate-800 p-6 rounded-lg text-center hover:border-${color}-500 transition-colors group`}>
      <label className="cursor-pointer block">
        <div className={`mb-2 text-${color}-400 font-semibold uppercase tracking-wider text-sm`}>
          {label}
        </div>
        <div className="text-slate-400 text-xs mb-4 group-hover:text-slate-200">
          {accept === ".xml" ? "Drag & Drop XML Config" : "Drag & Drop CSV Logs"}
        </div>
        <input 
          type="file" 
          accept={accept} 
          onChange={handleFileChange} 
          className="hidden" 
        />
        <span className={`inline-block px-4 py-2 bg-slate-700 text-${color}-400 rounded hover:bg-slate-600 transition text-sm font-medium`}>
          Select File
        </span>
      </label>
    </div>
  );
};
