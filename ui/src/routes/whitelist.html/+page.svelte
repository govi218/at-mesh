<script lang="ts">
	import { onMount } from 'svelte';
	import { fade } from 'svelte/transition';
	import { getWhitelist, addWhitelistEntry, deleteWhitelistEntry, type WhitelistEntry } from '$lib/whitelist/apiFunctions.svelte';
	import { alertStore } from '$lib/common/stores.js';

	let componentLoaded = false;
	let entries: WhitelistEntry[] = [];
	let error = '';
	let showAddForm = false;

	// form fields
	let newDID = '';
	let newHandle = '';
	let newMaxNodes = 0;
	let newNotes = '';

	async function loadWhitelist() {
		try {
			entries = await getWhitelist();
			error = '';
		} catch (e) {
			error = String(e);
			entries = [];
		}
	}

	async function handleAdd() {
		try {
			await addWhitelistEntry(newDID, newHandle, newMaxNodes, newNotes);
			newDID = '';
			newHandle = '';
			newMaxNodes = 0;
			newNotes = '';
			showAddForm = false;
			await loadWhitelist();
			$alertStore = 'Added whitelist entry';
		} catch (e) {
			$alertStore = 'Error: ' + String(e);
		}
	}

	async function handleDelete(id: number) {
		try {
			await deleteWhitelistEntry(id);
			await loadWhitelist();
			$alertStore = 'Removed whitelist entry';
		} catch (e) {
			$alertStore = 'Error: ' + String(e);
		}
	}

	onMount(async () => {
		await loadWhitelist();
		componentLoaded = true;
	});
</script>

{#if componentLoaded}
	<div in:fade|global>
		<div class="px-4 pt-4">
			<h1 class="text-2xl bold text-primary">Whitelist</h1>
			<p class="text-sm text-base-content mt-1">
				Only AT Protocol DIDs in this list can join the mesh. Empty list = allow all (bootstrap mode).
			</p>
		</div>

		<div class="px-4 py-4">
			{#if !showAddForm}
				<button on:click={() => (showAddForm = true)} class="btn btn-primary btn-xs capitalize" type="button">+ Add Entry</button>
			{:else}
				<button on:click={() => (showAddForm = false)} class="btn btn-secondary btn-xs capitalize" type="button">- Hide Form</button>
			{/if}
		</div>

		{#if showAddForm}
			<div class="px-4 pb-4" in:fade|global>
				<form on:submit|preventDefault={handleAdd} class="flex flex-col gap-2 max-w-lg">
					<label class="block text-secondary text-sm font-bold" for="did">DID (required)</label>
					<input id="did" bind:value={newDID} class="form-input" placeholder="did:plc:..." required />

					<label class="block text-secondary text-sm font-bold" for="handle">Handle</label>
					<input id="handle" bind:value={newHandle} class="form-input" placeholder="user.bsky.social" />

					<label class="block text-secondary text-sm font-bold" for="maxnodes">Max Nodes</label>
					<input id="maxnodes" type="number" bind:value={newMaxNodes} class="form-input" placeholder="0 = unlimited" />

					<label class="block text-secondary text-sm font-bold" for="notes">Notes</label>
					<input id="notes" bind:value={newNotes} class="form-input" placeholder="optional" />

					<button type="submit" class="btn btn-primary btn-sm capitalize mt-2">Add to Whitelist</button>
				</form>
			</div>
		{/if}

		{#if error}
			<div class="px-4 py-4 text-error">
				<p>{error}</p>
				<p class="text-sm mt-2">Make sure you are logged in as admin. <a href="/admin/login" class="link link-primary">Login here</a>.</p>
			</div>
		{:else if entries.length === 0}
			<div class="px-4 py-4 text-base-content">
				<p>Whitelist is empty — all DIDs are allowed (bootstrap mode).</p>
			</div>
		{:else}
			<div class="px-4 overflow-x-auto">
				<table class="table table-zebra">
					<thead>
						<tr>
							<th>DID</th>
							<th>Handle</th>
							<th>Max Nodes</th>
							<th>Notes</th>
							<th>Created</th>
							<th></th>
						</tr>
					</thead>
					<tbody>
						{#each entries as entry}
							<tr>
								<td class="font-mono text-xs">{entry.did}</td>
								<td>{entry.handle || '-'}</td>
								<td>{entry.max_nodes || '∞'}</td>
								<td>{entry.notes || '-'}</td>
								<td class="text-xs">{new Date(entry.created_at).toLocaleDateString()}</td>
								<td>
									<button
										on:click={() => handleDelete(entry.id)}
										class="btn btn-error btn-xs capitalize"
										type="button"
									>Remove</button>
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		{/if}
	</div>
{/if}
