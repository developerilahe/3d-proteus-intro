import { useMemo, useState } from 'react';
import { geoGraticule10, geoNaturalEarth1, geoPath } from 'd3-geo';
import { feature } from 'topojson-client';
import type { GeoJsonProperties, Geometry } from 'geojson';
import type { Topology, GeometryCollection } from 'topojson-specification';
import worldAtlas from 'world-atlas/countries-110m.json';
import type { GeoPointDto } from '../../types/proteus-api.ts';
import { DomainWithConfusables } from './shared.tsx';

interface WorldThreatMapProps {
  geo: GeoPointDto[];
  inspectedCountry: GeoPointDto | null;
  onSelectCountry: (country: GeoPointDto | null) => void;
  onSelectDomain: (domain: string) => void;
}

interface CountryProps extends Record<string, unknown> {
  name?: string;
}

const ISO2_TO_NUMERIC: Record<string, string> = {
  AE: '784',
  AR: '032',
  AT: '040',
  AU: '036',
  AZ: '031',
  BE: '056',
  BG: '100',
  BR: '076',
  BY: '112',
  CA: '124',
  CH: '756',
  CL: '152',
  CN: '156',
  CO: '170',
  CZ: '203',
  DE: '276',
  DK: '208',
  EE: '233',
  EG: '818',
  ES: '724',
  FI: '246',
  FR: '250',
  GB: '826',
  GE: '268',
  GR: '300',
  HK: '344',
  HR: '191',
  HU: '348',
  ID: '360',
  IE: '372',
  IL: '376',
  IN: '356',
  IR: '364',
  IS: '352',
  IT: '380',
  JP: '392',
  KR: '410',
  KZ: '398',
  LT: '440',
  LU: '442',
  LV: '428',
  MA: '504',
  MD: '498',
  MX: '484',
  MY: '458',
  NG: '566',
  NL: '528',
  NO: '578',
  NZ: '554',
  PA: '591',
  PH: '608',
  PK: '586',
  PL: '616',
  PT: '620',
  QA: '634',
  RO: '642',
  RS: '688',
  RU: '643',
  SA: '682',
  SE: '752',
  SG: '702',
  SK: '703',
  TH: '764',
  TR: '792',
  TW: '158',
  UA: '804',
  US: '840',
  UZ: '860',
  VN: '704',
  ZA: '710',
};

const SVG_WIDTH = 960;
const SVG_HEIGHT = 480;

function toLonLat(coords: [number, number]): [number, number] {
  const lon = coords[0] * 360 - 180;
  const lat = 90 - coords[1] * 180;
  return [lon, lat];
}

function pinSeverity(g: GeoPointDto): 'crit' | 'watch' | 'low' {
  if (g.threats > 3) return 'crit';
  if (g.threats > 0) return 'watch';
  return 'low';
}

export function WorldThreatMap({
  geo,
  inspectedCountry,
  onSelectCountry,
  onSelectDomain,
}: WorldThreatMapProps) {
  const [hoveredCode, setHoveredCode] = useState<string | null>(null);

  const mapGeometry = useMemo(() => {
    const topology = worldAtlas as unknown as Topology<{
      countries: GeometryCollection<CountryProps>;
    }>;
    const fc = feature(topology, topology.objects.countries);
    // Exclude Antarctica ('010') so populated landmasses fill the canvas cleanly
    const features = fc.features.filter((f) => String(f.id ?? '') !== '010');

    const projection = geoNaturalEarth1().fitExtent(
      [
        [14, 14],
        [SVG_WIDTH - 14, SVG_HEIGHT - 14],
      ],
      { type: 'Sphere' }
    );
    const pathGen = geoPath(projection);
    const spherePath = pathGen({ type: 'Sphere' }) ?? '';
    const graticulePath = pathGen(geoGraticule10()) ?? '';

    const countries = features.map((f, index) => ({
      id: String(f.id ?? index),
      name: String((f.properties as GeoJsonProperties & CountryProps)?.name ?? ''),
      d: pathGen(f as GeoJSON.Feature<Geometry, CountryProps>) ?? '',
    }));

    return { projection, spherePath, graticulePath, countries };
  }, []);

  const sortedGeo = useMemo(
    () =>
      [...geo].sort((a, b) => {
        if (b.threats !== a.threats) return b.threats - a.threats;
        return b.count - a.count;
      }),
    [geo]
  );

  const projectedPins = useMemo(() => {
    return sortedGeo
      .map((g) => {
        const pt = mapGeometry.projection(toLonLat(g.coords));
        if (!pt) return null;
        return {
          geo: g,
          x: pt[0],
          y: pt[1],
          severity: pinSeverity(g),
          numericId: ISO2_TO_NUMERIC[g.code.toUpperCase()] ?? '',
        };
      })
      .filter((p): p is NonNullable<typeof p> => p !== null);
  }, [sortedGeo, mapGeometry]);

  const pinByNumericId = useMemo(() => {
    const map = new Map<string, GeoPointDto>();
    for (const p of projectedPins) {
      if (p.numericId) map.set(p.numericId, p.geo);
    }
    return map;
  }, [projectedPins]);

  // Subtle infrastructure connection arcs from the primary hotspot to other threat hubs
  const networkArcs = useMemo(() => {
    const active = projectedPins.filter((p) => p.geo.threats > 0);
    if (active.length < 2) return [];
    const hub = active[0];
    return active.slice(1, 7).map((target) => {
      const mx = (hub.x + target.x) / 2;
      const my = (hub.y + target.y) / 2;
      const dist = Math.hypot(target.x - hub.x, target.y - hub.y);
      const lift = Math.min(80, Math.max(24, dist * 0.22));
      return {
        key: `${hub.geo.code}-${target.geo.code}`,
        d: `M ${hub.x.toFixed(1)} ${hub.y.toFixed(1)} Q ${mx.toFixed(1)} ${(my - lift).toFixed(1)} ${target.x.toFixed(1)} ${target.y.toFixed(1)}`,
        isFocused:
          inspectedCountry?.code === target.geo.code ||
          inspectedCountry?.code === hub.geo.code,
      };
    });
  }, [projectedPins, inspectedCountry]);

  const totalMapped = useMemo(
    () => geo.reduce((sum, g) => sum + g.count, 0),
    [geo]
  );
  const totalThreats = useMemo(
    () => geo.reduce((sum, g) => sum + g.threats, 0),
    [geo]
  );

  return (
    <div id="map-geo" className="map-pane active">
      <div className="threat-map-layout">
        {/* Left: Cartographic World Map */}
        <div className="threat-map-canvas-col">
          <div className="threat-map-stage">
            <svg
              id="world-svg"
              viewBox={`0 0 ${SVG_WIDTH} ${SVG_HEIGHT}`}
              preserveAspectRatio="xMidYMid meet"
              role="img"
              aria-label="Global threat infrastructure distribution map"
            >
              <defs>
                <radialGradient id="ocean-globe-grad" cx="50%" cy="46%" r="58%">
                  <stop offset="0%" stopColor="#141726" />
                  <stop offset="100%" stopColor="#0a0b10" />
                </radialGradient>
                <clipPath id="globe-sphere-clip">
                  <path d={mapGeometry.spherePath} />
                </clipPath>
              </defs>

              {/* Globe Sphere */}
              <path
                d={mapGeometry.spherePath}
                fill="url(#ocean-globe-grad)"
                stroke="#2f2b28"
                strokeWidth="1.2"
              />

              {/* Lat/Lon Graticules */}
              <path
                d={mapGeometry.graticulePath}
                fill="none"
                stroke="#1c2033"
                strokeWidth="0.6"
                clipPath="url(#globe-sphere-clip)"
              />

              {/* World Countries */}
              <g id="world-continents" clipPath="url(#globe-sphere-clip)">
                {mapGeometry.countries.map((c) => {
                  const matchedGeo = pinByNumericId.get(c.id);
                  const isSelected =
                    matchedGeo && inspectedCountry?.code === matchedGeo.code;
                  const isHovered =
                    matchedGeo && hoveredCode === matchedGeo.code;

                  let fill = '#1d2134';
                  let stroke = '#384060';
                  let strokeWidth = 0.65;

                  if (isSelected) {
                    fill = '#333880';
                    stroke = '#7d82ff';
                    strokeWidth = 1.1;
                  } else if (isHovered) {
                    fill = '#2a2f5c';
                    stroke = '#656be0';
                    strokeWidth = 0.9;
                  } else if (matchedGeo) {
                    fill =
                      matchedGeo.threats > 0 ? '#242947' : '#20243b';
                    stroke =
                      matchedGeo.threats > 3
                        ? 'rgba(255, 90, 90, 0.5)'
                        : matchedGeo.threats > 0
                          ? 'rgba(255, 200, 87, 0.42)'
                          : '#444c72';
                  }

                  return (
                    <path
                      key={c.id}
                      d={c.d}
                      fill={fill}
                      stroke={stroke}
                      strokeWidth={strokeWidth}
                      strokeLinejoin="round"
                      style={{
                        cursor: matchedGeo ? 'pointer' : 'default',
                        transition: 'fill 160ms ease, stroke 160ms ease',
                      }}
                      onMouseEnter={() => {
                        if (matchedGeo) setHoveredCode(matchedGeo.code);
                      }}
                      onMouseLeave={() => {
                        if (matchedGeo) setHoveredCode(null);
                      }}
                      onClick={() => {
                        if (matchedGeo) onSelectCountry(matchedGeo);
                      }}
                    >
                      <title>
                        {matchedGeo
                          ? `${matchedGeo.name} (${matchedGeo.code}) · ${matchedGeo.count} domains · ${matchedGeo.threats} threats`
                          : c.name}
                      </title>
                    </path>
                  );
                })}
              </g>

              {/* Threat Cluster Connection Arcs */}
              <g id="threat-arcs" clipPath="url(#globe-sphere-clip)" pointerEvents="none">
                {networkArcs.map((arc) => (
                  <path
                    key={arc.key}
                    d={arc.d}
                    fill="none"
                    stroke={arc.isFocused ? '#7d82ff' : '#4246ce'}
                    strokeOpacity={arc.isFocused ? 0.65 : 0.28}
                    strokeWidth={arc.isFocused ? 1.5 : 1}
                    strokeDasharray="4 4"
                  />
                ))}
              </g>

              {/* Country Pins & Readable Pill Labels */}
              <g id="country-pins">
                {projectedPins.map(({ geo: g, x, y, severity }) => {
                  const r = Math.max(5.5, Math.min(13, 5 + Math.sqrt(g.count) * 2.1));
                  const isSelected = inspectedCountry?.code === g.code;
                  const isHovered = hoveredCode === g.code;
                  const pinFill =
                    severity === 'crit'
                      ? '#FF5A5A'
                      : severity === 'watch'
                        ? '#FFC857'
                        : '#6DD98A';
                  const labelText = `${g.code} · ${g.count}`;
                  const pillW = Math.max(46, labelText.length * 6.5 + 12);
                  const pillY = y - r - 23;

                  return (
                    <g
                      key={g.code}
                      className="pin"
                      role="button"
                      tabIndex={0}
                      aria-label={`${g.name}: ${g.count} domains, ${g.threats} threats`}
                      onMouseEnter={() => setHoveredCode(g.code)}
                      onMouseLeave={() => setHoveredCode(null)}
                      onClick={() => onSelectCountry(g)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' || e.key === ' ') {
                          e.preventDefault();
                          onSelectCountry(g);
                        }
                      }}
                    >
                      {/* Outer Radar Ring */}
                      <circle
                        cx={x}
                        cy={y}
                        r={r + (isSelected ? 8 : 5)}
                        fill="none"
                        stroke={isSelected ? '#7d82ff' : pinFill}
                        strokeOpacity={isSelected || isHovered ? 0.9 : 0.4}
                        strokeWidth={isSelected ? 1.8 : 1.1}
                        strokeDasharray={isSelected ? undefined : '2.5 2.5'}
                      />
                      {/* Ambient Halo */}
                      <circle
                        cx={x}
                        cy={y}
                        r={r + 2}
                        fill={pinFill}
                        fillOpacity={isSelected ? 0.25 : 0.14}
                      />
                      {/* Core Pin */}
                      <circle
                        cx={x}
                        cy={y}
                        r={r}
                        fill={pinFill}
                        stroke="#07080A"
                        strokeWidth="1.5"
                      />
                      {/* Pill Label for Guaranteed Contrast */}
                      <rect
                        x={x - pillW / 2}
                        y={pillY}
                        width={pillW}
                        height={17}
                        rx={3}
                        fill="#07080A"
                        fillOpacity={0.92}
                        stroke={isSelected ? '#7d82ff' : '#1E2430'}
                        strokeWidth={isSelected ? 1.1 : 0.8}
                      />
                      <text
                        x={x}
                        y={pillY + 12}
                        textAnchor="middle"
                        className="pin-label"
                        fill={isSelected ? '#ffffff' : '#e6e6e6'}
                      >
                        {labelText}
                      </text>
                      <title>
                        {g.name} ({g.code}) · {g.count} domains · {g.threats} threats
                      </title>
                    </g>
                  );
                })}
              </g>
            </svg>
          </div>

          <div id="geo-legend" className="geo-legend">
            <div className="legend-item">
              <span className="legend-dot" style={{ background: 'var(--crit)' }} />
              <span>Critical (&gt;3 active)</span>
            </div>
            <div className="legend-item">
              <span className="legend-dot" style={{ background: 'var(--watch)' }} />
              <span>Active (1–3 active)</span>
            </div>
            <div className="legend-item">
              <span className="legend-dot" style={{ background: 'var(--low)' }} />
              <span>Low / Inactive</span>
            </div>
            <div className="legend-summary">
              {geo.length} regions · {totalMapped} domains · {totalThreats} threats
            </div>
          </div>
        </div>

        {/* Right: Side-by-Side Country Inspector & Ranked Hotspots */}
        <aside className="threat-map-sidebar" aria-label="Regional Infrastructure Inspector">
          {inspectedCountry ? (
            <div id="geo-inspector" className="geo-inspector-panel">
              <div className="geo-inspector-top">
                <button
                  type="button"
                  className="geo-back-btn"
                  onClick={() => onSelectCountry(null)}
                >
                  ← All Regions
                </button>
                <span className="geo-code-chip">{inspectedCountry.code}</span>
              </div>

              <h3 className="geo-country-title">{inspectedCountry.name}</h3>

              <div className="geo-country-metrics">
                <div>
                  <span className="geo-metric-label">Domains</span>
                  <strong className="geo-metric-val">{inspectedCountry.count}</strong>
                </div>
                <div>
                  <span className="geo-metric-label">Live Threats</span>
                  <strong
                    className="geo-metric-val"
                    style={{
                      color:
                        inspectedCountry.threats > 0 ? 'var(--crit)' : 'var(--text)',
                    }}
                  >
                    {inspectedCountry.threats}
                  </strong>
                </div>
              </div>

              <div className="geo-asn-block">
                <span className="geo-section-kicker">Autonomous Systems</span>
                <p className="geo-asn-text">
                  {inspectedCountry.asns.join(', ') || 'No ASN metadata'}
                </p>
              </div>

              <div className="geo-domains-block">
                <span className="geo-section-kicker">
                  Mapped Domains ({inspectedCountry.domains.length})
                </span>
                <div className="geo-domain-list">
                  {inspectedCountry.domains.map((d) => (
                    <button
                      key={d}
                      type="button"
                      className="geo-domain-link"
                      onClick={() => onSelectDomain(d)}
                      title="Open domain in Triage Dossier"
                    >
                      <span className="geo-domain-name">
                        <DomainWithConfusables domain={d} />
                      </span>
                      <span className="geo-domain-arrow" aria-hidden="true">
                        ↗
                      </span>
                    </button>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="geo-regions-panel">
              <div className="geo-regions-head">
                <span className="geo-section-kicker">Active Regions</span>
                <span className="geo-regions-count">{sortedGeo.length}</span>
              </div>
              {sortedGeo.length === 0 ? (
                <div className="empty-state">No geographic telemetry mapped yet.</div>
              ) : (
                <div className="geo-region-list">
                  {sortedGeo.map((g) => {
                    const sev = pinSeverity(g);
                    return (
                      <button
                        key={g.code}
                        type="button"
                        className="geo-region-row"
                        onClick={() => onSelectCountry(g)}
                        onMouseEnter={() => setHoveredCode(g.code)}
                        onMouseLeave={() => setHoveredCode(null)}
                      >
                        <div className="geo-region-main">
                          <span
                            className={`geo-status-dot sev-${sev}`}
                            aria-hidden="true"
                          />
                          <div className="geo-region-names">
                            <span className="geo-region-name">{g.name}</span>
                            <span className="geo-region-sub">
                              {g.code} · {g.asns[0] || 'No ASN'}
                            </span>
                          </div>
                        </div>
                        <div className="geo-region-counts">
                          <span className="geo-region-count">{g.count}</span>
                          {g.threats > 0 && (
                            <span className="geo-region-threat">
                              {g.threats} live
                            </span>
                          )}
                        </div>
                      </button>
                    );
                  })}
                </div>
              )}
            </div>
          )}
        </aside>
      </div>
    </div>
  );
}
