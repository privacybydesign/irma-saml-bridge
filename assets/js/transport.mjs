// Posts a JSON object to the given URL and returns the HTTP status and the parsed JSON response.
async function postJson(url, object) {
    const resp = await fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(object),
    });
    return {
        status: resp.status,
        data: resp.status === 200 ? await resp.json() : null,
    }
}

export { postJson };
