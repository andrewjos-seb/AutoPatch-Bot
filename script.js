document.getElementById('scanButton').addEventListener('click', scan);

const GITHUB_API_URL = 'https://api.github.com';
let lastScannedCommit = {};

async function scan() {
    const githubToken = document.getElementById('githubToken').value;
    const repoOwner = document.getElementById('repoOwner').value;
    const repoName = document.getElementById('repoName').value;
    const branchName = document.getElementById('branchName').value;
    const geminiApiKey = document.getElementById('geminiApiKey').value;
    const resultsContainer = document.getElementById('results');

    if (!githubToken || !repoOwner || !repoName || !branchName || !geminiApiKey) {
        alert('Please fill in all fields.');
        return;
    }

    resultsContainer.innerHTML = 'Scanning...';

    try {
        const commits = await getCommits(githubToken, repoOwner, repoName, branchName);
        if (commits.length === 0) {
            resultsContainer.innerHTML = 'No new commits found.';
            return;
        }

        let resultsHtml = '';
        for (const commit of commits) {
            resultsHtml += `<div class="commit">
                <h3>${commit.commit.message}</h3>
                <p>Author: ${commit.commit.author.name}</p>
                <p>Date: ${new Date(commit.commit.author.date).toLocaleString()}</p>
            `;

            const files = await getCommitFiles(githubToken, repoOwner, repoName, commit.sha);
            for (const file of files) {
                resultsHtml += `<div class="file">
                    <h4>${file.filename}</h4>
                `;

                if (file.status === 'removed') {
                    resultsHtml += '<p>File removed.</p></div>';
                    continue;
                }
                
                const content = await getFileContent(githubToken, repoOwner, repoName, file.sha);
                const decodedContent = atob(content); // content is base64 encoded
                const analysisResults = await analyzeContent(geminiApiKey, decodedContent);

                if (analysisResults && analysisResults.length > 0) {
                    for (const result of analysisResults) {
                        resultsHtml += `<div class="vulnerability">
                            <p><strong>Vulnerability:</strong> ${result.vulnerability_found}</p>
                            <p><strong>Explanation:</strong> ${result.explanation}</p>
                            <p><strong>Suggested Fix:</strong> <pre><code>${result.suggested_fix}</code></pre></p>
                            <p><strong>Confidence:</strong> ${result.confidence_score}</p>
                        </div>`;
                    }
                } else {
                    resultsHtml += '<p>No vulnerabilities found.</p>';
                }
                resultsHtml += '</div>';
            }
            resultsHtml += '</div>';
        }

        resultsContainer.innerHTML = resultsHtml;
        if (commits.length > 0) {
            lastScannedCommit[branchName] = commits[0].sha;
        }

    } catch (error) {
        console.error('Error during scan:', error);
        resultsContainer.innerHTML = `Error: ${error.message}`;
    }
}

async function getCommits(token, owner, repo, branch) {
    const url = `${GITHUB_API_URL}/repos/${owner}/${repo}/commits?sha=${branch}`;
    const headers = { 'Authorization': `token ${token}` };
    
    // If we have scanned this branch before, only fetch commits since the last one.
    if (lastScannedCommit[branch]) {
        url += `&since=${lastScannedCommit[branch]}`;
    }

    const response = await fetch(url, { headers });
    if (!response.ok) {
        throw new Error(`GitHub API error: ${response.status} ${response.statusText}`);
    }
    const commits = await response.json();
    
    // The 'since' parameter can sometimes include the last scanned commit, so we filter it out.
    return commits.filter(c => !lastScannedCommit[branch] || c.sha !== lastScannedCommit[branch]);
}

async function getCommitFiles(token, owner, repo, commitSha) {
    const url = `${GITHUB_API_URL}/repos/${owner}/${repo}/commits/${commitSha}`;
    const headers = { 'Authorization': `token ${token}` };
    const response = await fetch(url, { headers });
    if (!response.ok) {
        throw new Error(`GitHub API error: ${response.status} ${response.statusText}`);
    }
    const commitData = await response.json();
    return commitData.files;
}

async function getFileContent(token, owner, repo, fileSha) {
    const url = `${GITHUB_API_URL}/repos/${owner}/${repo}/git/blobs/${fileSha}`;
    const headers = { 'Authorization': `token ${token}` };
    const response = await fetch(url, { headers });
    if (!response.ok) {
        throw new Error(`GitHub API error: ${response.status} ${response.statusText}`);
    }
    const blobData = await response.json();
    return blobData.content;
}

async function analyzeContent(apiKey, fileContent) {
    const GEMINI_API_URL = `https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key=${apiKey}`;
    
    const prompt = `
    You are an expert AI security agent. Perform a security scan on the following source code.
    GOAL: Detect potential instances of vulnerabilities like SQL Injection, XSS, Hardcoded Secrets, etc.
    For EACH vulnerability found, output a separate, complete JSON object.
    If no vulnerabilities are found, return an empty list [].
    Analyze this code:
    ${fileContent}
    Respond ONLY with a list of JSON objects in this format:
    [
        {
            "vulnerability_found": "Name of vulnerability or 'None'",
            "explanation": "Why this is a risk.",
            "suggested_fix": "Code block to fix the issue.",
            "confidence_score": "1-10"
        }
    ]
    `;

    const payload = {
        "contents": [{
            "parts": [{
                "text": prompt
            }]
        }]
    };

    const response = await fetch(GEMINI_API_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    });

    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Gemini API error: ${response.status} ${response.statusText} - ${errorText}`);
    }

    const data = await response.json();
    const responseText = data.candidates[0].content.parts[0].text;
    
    try {
        // The response might be wrapped in markdown
        const jsonMatch = responseText.match(/```(?:json)?\s*(\[.*\])\s*```/s);
        if (jsonMatch) {
            return JSON.parse(jsonMatch[1]);
        } else {
            return JSON.parse(responseText);
        }
    } catch (e) {
        console.error("Failed to parse JSON from Gemini response:", responseText);
        return null;
    }
}

