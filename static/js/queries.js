// Polling interval in ms
const POLL_INTERVAL = 7000; // 7 seconds

// Utility to create element with text
function el(tag, text) {
  const e = document.createElement(tag);
  if (text) e.textContent = text;
  return e;
}

// Renders trainer queries into a container with id 'trainer-queries'
async function fetchAndRenderTrainerQueries() {
  try {
    const res = await fetch('/trainer/queries/json');
    if (!res.ok) {
      console.warn('Failed to fetch queries:', res.status);
      return;
    }
    const queries = await res.json();
    const container = document.getElementById('trainer-queries');
    if (!container) return;

    // Clear
    container.innerHTML = '';

    if (queries.length === 0) {
      container.appendChild(el('div', 'No queries at the moment.'));
      return;
    }

    const table = document.createElement('table');
    table.className = 'table table-sm table-striped';
    const thead = document.createElement('thead');
    thead.innerHTML = '<tr><th>#</th><th>Student</th><th>Batch</th><th>Message</th><th>Status</th><th>When</th><th>Action</th></tr>';
    table.appendChild(thead);
    const tbody = document.createElement('tbody');

    queries.forEach((q, idx) => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${idx+1}</td>
        <td>${q.user_name || 'Unknown'}</td>
        <td>${q.batch_name || '—'}</td>
        <td style="max-width:400px;word-wrap:break-word;">${q.message}</td>
        <td id="status-${q.id}">${q.status}</td>
        <td>${new Date(q.created_at).toLocaleString()}</td>
      `;

      const actionTd = document.createElement('td');

      // In Progress button
      const inProgBtn = document.createElement('button');
      inProgBtn.className = 'btn btn-sm btn-warning me-1';
      inProgBtn.textContent = 'In Progress';
      inProgBtn.onclick = () => updateQueryStatus(q.id, 'In Progress');

      // Resolved button
      const resBtn = document.createElement('button');
      resBtn.className = 'btn btn-sm btn-success';
      resBtn.textContent = 'Resolved';
      resBtn.onclick = () => updateQueryStatus(q.id, 'Resolved');

      actionTd.appendChild(inProgBtn);
      actionTd.appendChild(resBtn);

      tr.appendChild(actionTd);
      tbody.appendChild(tr);
    });

    table.appendChild(tbody);
    container.appendChild(table);

  } catch (err) {
    console.error('Error fetching trainer queries', err);
  }
}

async function updateQueryStatus(queryId, newStatus) {
  try {
    const res = await fetch(`/trainer/update_query_status/${queryId}`, {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({status:newStatus})
    });
    if (!res.ok) {
      const text = await res.text();
      alert('Failed to update: ' + text);
      return;
    }
    const data = await res.json();
    // reflect change in UI immediately
    const statusCell = document.getElementById(`status-${queryId}`);
    if (statusCell) statusCell.textContent = newStatus;
  } catch (err) {
    console.error('Error updating status', err);
  }
}

// Start polling when page loads (trainer dashboard)
document.addEventListener('DOMContentLoaded', function() {
  // Initial load
  fetchAndRenderTrainerQueries();
  // Poll
  setInterval(fetchAndRenderTrainerQueries, POLL_INTERVAL);
});
