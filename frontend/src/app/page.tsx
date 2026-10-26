const apiBase = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000";

export default function HomePage() {
  return (
    <main className="page">
      <div className="card">
        <span className="badge">Faz 01 — İskelet</span>
        <h1>ajant Güvenlik Paneli</h1>
        <p>
          Bu sayfa yer tutucudur. Genel bakış, olay listesi, olay detayı,
          sunucular, audit log ve ayarlar ekranları <strong>Faz 05</strong>
          &apos;te geliştirilecektir.
        </p>
        <ul>
          <li>
            Backend API: <code>{apiBase}</code>
          </li>
          <li>
            Sağlık kontrolü:{" "}
            <a href={`${apiBase}/api/v1/health`}>/api/v1/health</a>
          </li>
          <li>
            Politika modu: <strong>observe_only</strong> (yalnızca gözlem)
          </li>
        </ul>
      </div>
    </main>
  );
}
