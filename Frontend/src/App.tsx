import React, { useState, useEffect } from 'react';

interface DNSRecord {
  A?: string[];
  AAAA?: string[];
  MX?: string[];
  TXT?: string[];
  SOA?: string[];
  CAA?: string[];
}

interface IPData {
  [ip: string]: DNSRecord | {};
}

interface DNSData {
  [nameserver: string]: IPData;
}

const fetchDNSData = async (): Promise<DNSData> => {
  try {
    const response = await fetch('http://localhost:8080/dns-records', {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });
    const responseText = await response.text();
    if (!response.ok) {
      try {
        const errorData = JSON.parse(responseText);
        throw new Error(errorData.error || `HTTP error! Status: ${response.status}`);
      } catch {
        throw new Error(`HTTP error! Status: ${response.status}`);
      }
    }
    try {
      return JSON.parse(responseText.trim());
    } catch (parseError) {
      throw new Error(`Failed to parse JSON: ${responseText}`);
    }
  } catch (error) {
    console.error('Fetch error:', error);
    throw error;
  }
};

type RecordGroupProps = {
  type: string;
  values: string[];
};

const RecordGroup = ({ type, values }: RecordGroupProps) => (
  <div className="mb-4">
    <h4 className="text-sm font-semibold text-indigo-600">{type}</h4>
    <ul className="list-disc list-inside text-gray-800 text-sm pl-4">
      {values.map((value, idx) => (
        <li key={idx} className="break-words">{value}</li>
      ))}
    </ul>
  </div>
);

type IPSectionProps = {
  ip: string;
  records: Record<string, string[]> | undefined;
};

const IPSection = ({ ip, records }: IPSectionProps) => (
  <div className="mb-6 p-4 bg-gray-50 rounded-lg shadow-inner">
    <p className="font-mono text-sm text-gray-500 mb-2">{ip}</p>
    {records && Object.entries(records).length > 0 ? (
      Object.entries(records).map(([type, values]) => (
        <RecordGroup key={type} type={type} values={values} />
      ))
    ) : (
      <p className="text-sm text-gray-400 italic">No records available</p>
    )}
  </div>
);

type NameServerSectionProps = {
  server: string;
  records: Record<string, any>;
};

const NameServerSection = ({ server, records }: NameServerSectionProps) => (
  <section className="min-w-[400px] w-[400px] mx-3 bg-white rounded-lg shadow-md p-6">
    <h2 className="text-xl font-bold text-gray-800 border-b pb-2 mb-4">{server}</h2>
    <div className="space-y-4">
      {Object.entries(records).map(([ip, rec]) => (
        <IPSection key={ip} ip={ip} records={rec} />
      ))}
    </div>
  </section>
);

export default function App() {
  const [dnsData, setDnsData] = useState<DNSData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [domain, setDomain] = useState<string>('');
  const [submitting, setSubmitting] = useState<boolean>(false);

  const loadData = async () => {
    try {
      const data = await fetchDNSData();
      setDnsData(data);
      setLoading(false);
    } catch (e) {
      setError('Не вийшло загрузити данні попробуйте пізніше');
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const submitDomain = async () => {
    if (!domain.trim()) return;
    setSubmitting(true);
    setError(null);

    try {
      const response = await fetch('http://localhost:8080/resolve', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: domain.trim() }),
      });

      if (response.ok) {
        console.log(response)
      }

      const data = await response.json();

      console.log(data)

      // Check if the response is valid
      if (data.status !== 'success') {
        setError('Домен неккоректний або непрацює');
        return;
      }

      // Refresh DNS data after resolving
      await loadData();
    } catch (err) {
      console.error('Error:', err);
      setError('Невийшло вирішити домен');
    } finally {
      setSubmitting(false);
    }
  };

  return (
   <main className="min-h-screen min-w-screen bg-gradient-to-b from-white to-gray-100 p-6 flex justify-center items-start">
      <div className="ml-[25vw] w-full max-w-4xl mx-auto flex flex-col items-center">
        <h1 className="text-4xl font-extrabold text-center text-gray-900 mb-6">DNS Records</h1>

        <div className="mb-6 text-center">
          <input
            type="text"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="Введіть домен"
            className="border border-gray-300 rounded-l px-4 py-2 w-64 text-sm"
          />
          <button
            onClick={submitDomain}
            disabled={submitting}
            className="bg-indigo-600 text-black px-4 py-2 rounded-r text-sm hover:bg-indigo-700 disabled:opacity-50"
          >
            Перевірити домен
          </button>
        </div>

        {loading ? (
          <div className="text-center text-gray-600 text-lg">Загрузка данних...</div>
        ) : error ? (
          <div className="text-center text-red-600 text-lg">{error}</div>
        ) : dnsData ? (
          <div className="flex flex-row gap-6 overflow-x-auto pb-4">
            {Object.entries(dnsData).map(([ns, records]) => (
              <NameServerSection key={ns} server={ns} records={records} />
            ))}
          </div>
        ) : (
          <div className="text-center text-gray-600 text-lg">No data available</div>
        )}
      </div>
    </main>
  );
}
