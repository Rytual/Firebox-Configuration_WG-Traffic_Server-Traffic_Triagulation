import { GoogleGenAI } from "@google/genai";
import { AuditSummary } from '../types';

export const generateSecurityReport = async (summary: AuditSummary): Promise<string> => {
  if (!process.env.API_KEY) {
    return "Error: API Key is missing. Please ensure process.env.API_KEY is configured.";
  }

  const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });
  
  // Construct a compact prompt to avoid token limits
  const prompt = `
    You are a Senior Security Auditor using the Sentinel Firewall Auditor tool.
    Analyze the following audit summary and write a professional, executive-level security report.
    
    DATA SUMMARY:
    - WatchGuard Gateway Logs Analyzed: ${summary.totalWatchGuardLogs}
    - Windows Server Logs Analyzed: ${summary.totalWindowsLogs}
    - Active Firewall Policies: ${summary.policyCount}
    
    KEY FINDINGS:
    - Blind Spots (Lateral Movement/Bypass): ${summary.blindSpots.length} identified.
      (Example: ${summary.blindSpots[0]?.description || 'None'})
    - Policy Violations (Misconfigurations): ${summary.violations.length} identified.
      (Example: ${summary.violations[0]?.description || 'None'})
    
    INSTRUCTIONS:
    1. Executive Summary of the security posture.
    2. Detailed analysis of the "Blind Spots" (traffic seen on servers but not gateway). Explain why this is dangerous (lateral movement).
    3. Detailed analysis of "Policy Violations".
    4. Remediation Steps: Concrete configuration changes for WatchGuard.
    5. Tone: Professional, authoritative, urgent if high risks found.
    6. Format: Markdown.
  `;

  try {
    const response = await ai.models.generateContent({
      model: 'gemini-2.5-flash',
      contents: prompt,
    });
    return response.text || "No report generated.";
  } catch (error) {
    console.error("Gemini API Error:", error);
    return "Failed to generate AI report due to an API error.";
  }
};
