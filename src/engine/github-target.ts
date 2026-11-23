const github = /^https:\/\/github\.com\/[a-z\d](?:[a-z\d-]{0,37}[a-z\d])?\/[a-z\d_][a-z\d_.-]{0,99}$/i;

export const invalidGitHubTarget = 'Enter https://github.com/<owner>/<repo> with no suffix.';

export function isGitHubUrl(value: string): boolean {
  return value.startsWith('https://github.com/') && github.test(value) && !value.endsWith('.') && !/\s/.test(value);
}
