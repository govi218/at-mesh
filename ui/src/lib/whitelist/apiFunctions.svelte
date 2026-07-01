<script context="module" lang="ts">
	export interface WhitelistEntry {
		id: number;
		did: string;
		handle: string;
		max_nodes: number;
		notes: string;
		created_at: string;
	}

	export async function getWhitelist(): Promise<WhitelistEntry[]> {
		let entries: WhitelistEntry[] = [];
		const response = await fetch('/api/v1/whitelist', {
			method: 'GET',
			headers: { Accept: 'application/json' },
			credentials: 'same-origin'
		});
		if (!response.ok) {
			throw await response.text();
		}
		entries = await response.json();
		return entries;
	}

	export async function addWhitelistEntry(
		did: string,
		handle: string,
		maxNodes: number,
		notes: string
	): Promise<WhitelistEntry> {
		const response = await fetch('/api/v1/whitelist', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
			credentials: 'same-origin',
			body: JSON.stringify({
				did,
				handle,
				max_nodes: maxNodes,
				notes
			})
		});
		if (!response.ok) {
			const text = await response.text();
			try {
				throw JSON.parse(text).error;
			} catch {
				throw text;
			}
		}
		return await response.json();
	}

	export async function deleteWhitelistEntry(id: number): Promise<void> {
		const response = await fetch(`/api/v1/whitelist/${id}`, {
			method: 'DELETE',
			headers: { Accept: 'application/json' },
			credentials: 'same-origin'
		});
		if (!response.ok) {
			const text = await response.text();
			try {
				throw JSON.parse(text).error;
			} catch {
				throw text;
			}
		}
	}
</script>
