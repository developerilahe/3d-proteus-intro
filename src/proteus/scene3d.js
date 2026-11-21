/**
 * PROTEUS — 8-Module Isometric 3D Architectural Platform & Live URL Packet Router
 * Standalone Three.js Module (zero React/framework dependencies)
 */

import * as THREE from 'three';
import { OrbitControls } from 'three/addons/controls/OrbitControls.js';
import { RoomEnvironment } from 'three/addons/environments/RoomEnvironment.js';
import { BRAND_PROFILES, TECHNIQUES_17_WEIGHTS, WALKTHROUGH_STEPS } from './scenario-data.js';

// Pre-allocated scratch helpers (Zero-GC inside render loop)
const _vA = new THREE.Vector3();
const _vB = new THREE.Vector3();
const _qA = new THREE.Quaternion();
const _colorA = new THREE.Color();
const _up = new THREE.Vector3(0, 1, 0);

const PALETTE = {
  voidBg: 0x0d0d0d,
  slabSurface: 0x13161c,
  slabBevel: 0x191d25,
  slateBody: 0x20252e,
  slateActive: 0x2a303c,
  slateDim: 0x151820,
  slateRecess: 0x0f1217,
  titaniumTrim: 0x3b4352,
  edgeLine: 0x313846,
  amber: 0xe5a93c,
  rust: 0xe05252,
  watch: 0xe5a93c,
  slateBlue: 0x5b9bd5,
  mutedViolet: 0x9b7ede,
  sage: 0x5f9e7e,
  arcDim: 0x242934,
};

const _dimBodyColor = new THREE.Color(PALETTE.slateDim);
const _activeBodyColor = new THREE.Color(PALETTE.slateActive);

export const NODE_ANCHORS = {
  brandHQ: { id: 'brandHQ', position: [-6.6, 0, -2.1], labelHeight: 3.15 },
  permRack: { id: 'permRack', position: [-6.0, 0, 1.55], labelHeight: 2.25 },
  actorTerminal: { id: 'actorTerminal', position: [-2.6, 0, 2.3], labelHeight: 2.05 },
  inspectionGate: { id: 'inspectionGate', position: [-0.2, 0, 0.0], labelHeight: 3.05 },
  infraStack: { id: 'infraStack', position: [3.0, 0, -1.9], labelHeight: 2.85 },
  relayTower: { id: 'relayTower', position: [6.0, 0, -2.5], labelHeight: 3.35 },
  twinVaults: { id: 'twinVaults', position: [7.1, 0, 0.7], labelHeight: 2.85 },
  responseConsole: { id: 'responseConsole', position: [3.6, 0, 2.8], labelHeight: 2.25 },
};

function easeInOutCubic(x) {
  return x < 0.5 ? 4 * x * x * x : 1 - Math.pow(-2 * x + 2, 3) / 2;
}

function detectSoftwareWebGL() {
  try {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl2') || canvas.getContext('webgl');
    if (!gl) return true;
    const ext = gl.getExtension('WEBGL_debug_renderer_info');
    const param = ext ? ext.UNMASKED_RENDERER_WEBGL : gl.RENDERER;
    const gpu = String(gl.getParameter(param) || '');
    gl.getExtension('WEBGL_lose_context')?.loseContext();
    return /SwiftShader|llvmpipe|softpipe|Software|Basic Render/i.test(gpu);
  } catch {
    return true;
  }
}

function createDotGridTexture(maxAnisotropy) {
  const size = 512;
  const canvas = document.createElement('canvas');
  canvas.width = size;
  canvas.height = size;
  const ctx = canvas.getContext('2d');
  if (!ctx) return null;

  ctx.fillStyle = '#13161C';
  ctx.fillRect(0, 0, size, size);

  const step = size / 16;
  ctx.fillStyle = 'rgba(140, 152, 178, 0.17)';
  for (let x = 0; x < 16; x++) {
    for (let y = 0; y < 16; y++) {
      ctx.beginPath();
      ctx.arc(x * step + step * 0.5, y * step + step * 0.5, 1.35, 0, Math.PI * 2);
      ctx.fill();
    }
  }

  const tex = new THREE.CanvasTexture(canvas);
  tex.colorSpace = THREE.SRGBColorSpace;
  tex.wrapS = THREE.RepeatWrapping;
  tex.wrapT = THREE.RepeatWrapping;
  tex.repeat.set(10, 6);
  tex.anisotropy = Math.min(8, maxAnisotropy || 1);
  tex.needsUpdate = true;
  return tex;
}

function createChamferedBox(w, d, h, bevel = 0.035) {
  const hw = Math.max(0.02, w / 2 - bevel);
  const hd = Math.max(0.02, d / 2 - bevel);
  const shape = new THREE.Shape();
  shape.moveTo(-hw, -hd);
  shape.lineTo(hw, -hd);
  shape.lineTo(hw, hd);
  shape.lineTo(-hw, hd);
  shape.closePath();

  const geo = new THREE.ExtrudeGeometry(shape, {
    depth: Math.max(0.02, h - bevel * 2),
    bevelEnabled: true,
    bevelThickness: bevel,
    bevelSize: bevel,
    bevelSegments: 2,
    steps: 1,
  });
  geo.rotateX(-Math.PI / 2);
  geo.computeBoundingBox();
  if (geo.boundingBox) geo.translate(0, -geo.boundingBox.min.y, 0);
  geo.computeVertexNormals();
  return geo;
}

function createRecessedFrame(outerW, outerD, innerW, innerD, h, bevel = 0.02) {
  const hw = outerW / 2 - bevel;
  const hd = outerD / 2 - bevel;
  const shape = new THREE.Shape();
  shape.moveTo(-hw, -hd);
  shape.lineTo(hw, -hd);
  shape.lineTo(hw, hd);
  shape.lineTo(-hw, hd);
  shape.closePath();

  const ihw = innerW / 2;
  const ihd = innerD / 2;
  const hole = new THREE.Path();
  hole.moveTo(-ihw, -ihd);
  hole.lineTo(-ihw, ihd);
  hole.lineTo(ihw, ihd);
  hole.lineTo(ihw, -ihd);
  hole.closePath();
  shape.holes.push(hole);

  const geo = new THREE.ExtrudeGeometry(shape, {
    depth: Math.max(0.02, h - bevel * 2),
    bevelEnabled: true,
    bevelThickness: bevel,
    bevelSize: bevel,
    bevelSegments: 2,
    steps: 1,
  });
  geo.rotateX(-Math.PI / 2);
  geo.computeBoundingBox();
  if (geo.boundingBox) geo.translate(0, -geo.boundingBox.min.y, 0);
  geo.computeVertexNormals();
  return geo;
}

export function createProteusScene3D(mountEl, options = {}) {
  if (!mountEl) throw new Error('createProteusScene3D requires a mount element.');

  const isSoftwareGl = detectSoftwareWebGL();
  const prefersReducedMotion =
    typeof window !== 'undefined' &&
    window.matchMedia &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  const callbacks = {
    onSelectNode: typeof options.onSelectNode === 'function' ? options.onSelectNode : () => {},
    onFrameProject:
      typeof options.onFrameProject === 'function' ? options.onFrameProject : () => {},
  };

  let currentStepIndex = Number.isInteger(options.initialStep)
    ? Math.max(0, Math.min(WALKTHROUGH_STEPS.length - 1, options.initialStep))
    : 0;
  let stepElapsed = 0;

  // Scene over #0A0B0D void
  const scene = new THREE.Scene();
  scene.background = new THREE.Color(PALETTE.voidBg);
  scene.fog = new THREE.FogExp2(PALETTE.voidBg, 0.013);

  const width = Math.max(320, mountEl.clientWidth || 1280);
  const height = Math.max(320, mountEl.clientHeight || 720);

  // Clean 3/4 isometric perspective (~38 deg elevation)
  const camera = new THREE.PerspectiveCamera(30, width / height, 0.1, 180);
  const initCam = WALKTHROUGH_STEPS[currentStepIndex].camera;
  camera.position.set(...initCam.position);

  const renderer = new THREE.WebGLRenderer({
    antialias: !isSoftwareGl,
    powerPreference: 'high-performance',
  });
  renderer.setSize(width, height);
  renderer.setPixelRatio(isSoftwareGl ? 1 : Math.min(window.devicePixelRatio || 1, 2));
  renderer.outputColorSpace = THREE.SRGBColorSpace;
  renderer.toneMapping = THREE.ACESFilmicToneMapping;
  renderer.toneMappingExposure = 0.96;
  renderer.shadowMap.enabled = !isSoftwareGl;
  renderer.shadowMap.type = THREE.PCFSoftShadowMap;
  renderer.domElement.style.display = 'block';
  renderer.domElement.style.width = '100%';
  renderer.domElement.style.height = '100%';
  renderer.domElement.style.outline = 'none';
  mountEl.appendChild(renderer.domElement);

  const pmrem = new THREE.PMREMGenerator(renderer);
  const envTex = pmrem.fromScene(new RoomEnvironment(), 0.04).texture;
  scene.environment = envTex;
  scene.environmentIntensity = 0.42;
  pmrem.dispose();

  // Calibrated Studio Lighting for Dark Charcoal Assemblies
  const hemiLight = new THREE.HemisphereLight(0x9aa8c2, 0x090b0f, 0.45);
  scene.add(hemiLight);

  const keyLight = new THREE.DirectionalLight(0xfff4e2, 1.45);
  keyLight.position.set(10, 18, 12);
  keyLight.castShadow = !isSoftwareGl;
  keyLight.shadow.mapSize.set(1024, 1024);
  keyLight.shadow.camera.near = 2;
  keyLight.shadow.camera.far = 52;
  const d = 17;
  keyLight.shadow.camera.left = -d;
  keyLight.shadow.camera.right = d;
  keyLight.shadow.camera.top = d;
  keyLight.shadow.camera.bottom = -d;
  keyLight.shadow.bias = -0.0005;
  keyLight.shadow.normalBias = 0.02;
  scene.add(keyLight);

  const rimLight = new THREE.DirectionalLight(0x7c98c4, 0.65);
  rimLight.position.set(-14, 10, -11);
  scene.add(rimLight);

  const controls = new OrbitControls(camera, renderer.domElement);
  controls.enableDamping = !isSoftwareGl;
  controls.dampingFactor = 0.08;
  controls.enableZoom = false;
  controls.minDistance = 7;
  controls.maxDistance = 34;
  controls.minPolarAngle = 0.25;
  controls.maxPolarAngle = Math.PI / 2 - 0.12;
  controls.target.set(...initCam.target);
  controls.update();

  let camTransition = false;
  const targetCamPos = new THREE.Vector3(...initCam.position);
  const targetLookAt = new THREE.Vector3(...initCam.target);
  controls.addEventListener('start', () => {
    camTransition = false;
  });

  // Resource tracking
  const geos = [];
  const mats = [];
  const texs = [];
  const trackG = (g) => (geos.push(g), g);
  const trackM = (m) => (mats.push(m), m);
  const trackT = (t) => (t && texs.push(t), t);

  const matSlabBevel = trackM(
    new THREE.MeshStandardMaterial({
      color: PALETTE.slabBevel,
      roughness: 0.72,
      metalness: 0.2,
    })
  );
  const matSlate = trackM(
    new THREE.MeshStandardMaterial({
      color: PALETTE.slateBody,
      roughness: 0.72,
      metalness: 0.22,
    })
  );
  const matRecess = trackM(
    new THREE.MeshStandardMaterial({
      color: PALETTE.slateRecess,
      roughness: 0.86,
      metalness: 0.12,
    })
  );
  const matTrimMetal = trackM(
    new THREE.MeshStandardMaterial({
      color: PALETTE.titaniumTrim,
      roughness: 0.34,
      metalness: 0.82,
    })
  );
  const matEdgeLine = trackM(
    new THREE.LineBasicMaterial({
      color: PALETTE.edgeLine,
      transparent: true,
      opacity: 0.82,
    })
  );

  const makeAccentMat = (hex) =>
    trackM(
      new THREE.MeshStandardMaterial({
        color: hex,
        roughness: 0.36,
        metalness: 0.45,
        emissive: new THREE.Color(hex),
        emissiveIntensity: 0.18,
      })
    );

  // =========================================================================
  // FLOATING ARCHITECTURAL PLATFORM SLAB (#16181D + Dot Grid + Beveled Edge)
  // =========================================================================
  const maxAniso = renderer.capabilities.getMaxAnisotropy();
  const dotTex = trackT(createDotGridTexture(maxAniso));

  const slabChassis = new THREE.Mesh(
    trackG(createChamferedBox(18.4, 9.8, 0.34, 0.08)),
    matSlabBevel
  );
  slabChassis.position.set(0.3, -0.34, 0.25);
  slabChassis.receiveShadow = true;
  const slabEdges = new THREE.EdgesGeometry(slabChassis.geometry, 25);
  trackG(slabEdges);
  slabChassis.add(new THREE.LineSegments(slabEdges, matEdgeLine));
  scene.add(slabChassis);

  const slabTopMat = trackM(
    new THREE.MeshStandardMaterial({
      map: dotTex,
      roughness: 0.88,
      metalness: 0.08,
      polygonOffset: true,
      polygonOffsetFactor: -1,
      polygonOffsetUnits: -1,
    })
  );
  const slabTop = new THREE.Mesh(trackG(new THREE.PlaneGeometry(18.1, 9.5)), slabTopMat);
  slabTop.rotation.x = -Math.PI / 2;
  slabTop.position.set(0.3, 0.004, 0.25);
  slabTop.receiveShadow = true;
  scene.add(slabTop);

  // Subtle architectural trace lines etched onto slab
  const traceMat = trackM(
    new THREE.LineBasicMaterial({
      color: 0x2b313d,
      transparent: true,
      opacity: 0.72,
    })
  );
  const tracePaths = [
    [
      [-6.6, 0.015, -2.1],
      [-6.0, 0.015, 1.55],
      [-2.6, 0.015, 2.3],
      [-0.2, 0.015, 0.0],
    ],
    [
      [-0.2, 0.015, 0.0],
      [3.0, 0.015, -1.9],
      [6.0, 0.015, -2.5],
    ],
    [
      [3.0, 0.015, -1.9],
      [7.1, 0.015, 0.7],
      [3.6, 0.015, 2.8],
    ],
  ];
  tracePaths.forEach((pts) => {
    const g = trackG(new THREE.BufferGeometry().setFromPoints(pts.map((p) => new THREE.Vector3(...p))));
    scene.add(new THREE.Line(g, traceMat));
  });

  // =========================================================================
  // NODE REGISTRY & HELPERS
  // =========================================================================
  const nodes = new Map();
  const hitProxies = [];

  const animHandles = {
    brandBeacon: null,
    permFins: [],
    infraRing: null,
    relaySweepRing: null,
    driftStackGroup: null,
    driftFlagMat: null,
    osintBayMats: [],
  };

  function registerNode(anchor, proxyDims) {
    const root = new THREE.Group();
    root.position.set(anchor.position[0], 0, anchor.position[2]);
    scene.add(root);

    const proxy = new THREE.Mesh(
      trackG(new THREE.BoxGeometry(proxyDims[0], proxyDims[1], proxyDims[2])),
      trackM(new THREE.MeshBasicMaterial({ visible: false }))
    );
    proxy.position.y = proxyDims[1] / 2;
    proxy.layers.set(1);
    proxy.userData.nodeId = anchor.id;
    root.add(proxy);
    hitProxies.push(proxy);

    const rec = {
      anchor,
      root,
      bodyMats: [],
      accentMats: [],
      edgeMats: [],
      baseEmissives: new Map(),
      activeWeight: 1,
    };
    nodes.set(anchor.id, rec);
    return rec;
  }

  function addPart(rec, geo, mat, pos = [0, 0, 0], rot = [0, 0, 0], opts = {}, parent = null) {
    const mesh = new THREE.Mesh(trackG(geo), mat);
    mesh.position.set(pos[0], pos[1], pos[2]);
    mesh.rotation.set(rot[0], rot[1], rot[2]);
    mesh.castShadow = true;
    mesh.receiveShadow = true;
    (parent || rec.root).add(mesh);

    if (opts.withEdges) {
      const eGeo = trackG(new THREE.EdgesGeometry(geo, opts.edgeThreshold ?? 22));
      const eMat = trackM(matEdgeLine.clone());
      rec.edgeMats.push(eMat);
      mesh.add(new THREE.LineSegments(eGeo, eMat));
    }
    if (opts.isAccent) {
      if (!rec.accentMats.includes(mat)) {
        rec.accentMats.push(mat);
        rec.baseEmissives.set(mat, mat.emissiveIntensity);
      }
    } else if (opts.isBody && !rec.bodyMats.includes(mat)) {
      rec.bodyMats.push(mat);
    }
    return mesh;
  }

  // =========================================================================
  // 1. LOOKALIKE SOURCE / CANDIDATE STATION (Outer Left, OFF Main Slab)
  // =========================================================================
  {
    const rec = registerNode(NODE_ANCHORS.actorTerminal, [2.4, 2.1, 2.3]);
    const bodyMat = trackM(matSlate.clone());
    const amberMat = makeAccentMat(PALETTE.amber);

    addPart(rec, createChamferedBox(2.4, 2.2, 0.24, 0.05), matSlabBevel, [0, -0.24, 0], [0, 0, 0], {
      withEdges: true,
    });
    addPart(rec, createRecessedFrame(2.16, 1.96, 1.94, 1.74, 0.06, 0.015), amberMat, [0, 0.0, 0], [0, 0, 0], {
      isAccent: true,
    });
    addPart(rec, createChamferedBox(1.35, 1.05, 0.5, 0.03), bodyMat, [0, 0.06, 0], [0, 0, 0], {
      isBody: true,
      withEdges: true,
    });
    addPart(rec, createChamferedBox(1.2, 0.2, 0.85, 0.02), bodyMat, [0, 0.54, -0.22], [-0.14, 0, 0], {
      isBody: true,
      withEdges: true,
    });
    addPart(rec, new THREE.BoxGeometry(1.0, 0.58, 0.04), matRecess, [0, 0.94, -0.15], [-0.14, 0, 0]);
    addPart(rec, new THREE.BoxGeometry(0.84, 0.045, 0.05), amberMat, [0, 1.19, -0.19], [-0.14, 0, 0], {
      isAccent: true,
    });
  }

  // =========================================================================
  // 2. TARGET BRAND ANCHOR (Left-Center on Slab)
  // =========================================================================
  {
    const rec = registerNode(NODE_ANCHORS.brandHQ, [2.4, 3.0, 2.2]);
    const bodyMat = trackM(matSlate.clone());
    const blueMat = makeAccentMat(PALETTE.slateBlue);

    addPart(rec, createChamferedBox(2.25, 2.05, 0.22, 0.03), bodyMat, [0, 0, 0], [0, 0, 0], {
      isBody: true,
      withEdges: true,
    });
    addPart(rec, createChamferedBox(1.75, 1.55, 1.42, 0.04), bodyMat, [0, 0.22, 0], [0, 0, 0], {
      isBody: true,
      withEdges: true,
    });
    for (let i = -2; i <= 2; i++) {
      addPart(rec, new THREE.BoxGeometry(0.075, 1.2, 1.64), matRecess, [i * 0.32, 0.93, 0]);
    }
    addPart(rec, createChamferedBox(1.12, 1.02, 0.42, 0.03), bodyMat, [0, 1.64, 0], [0, 0, 0], {
      isBody: true,
      withEdges: true,
    });
    addPart(rec, new THREE.CylinderGeometry(0.34, 0.4, 0.14, 24), matTrimMetal, [0, 2.13, 0]);
    animHandles.brandBeacon = addPart(
      rec,
      new THREE.CylinderGeometry(0.16, 0.16, 0.22, 20),
      blueMat,
      [0, 2.31, 0],
      [0, 0, 0],
      { isAccent: true }
    );
  }

  // =========================================================================
  // 3. 17-TECHNIQUE PERMUTATION RACK (Upper/Mid-Left on Slab)
  // =========================================================================
  {
    const rec = registerNode(NODE_ANCHORS.permRack, [2.7, 2.2, 2.3]);
    const bodyMat = trackM(matSlate.clone());
    const rustMat = makeAccentMat(PALETTE.rust);
    const amberMat = makeAccentMat(PALETTE.amber);
    const watchMat = makeAccentMat(PALETTE.watch);

    addPart(rec, createChamferedBox(2.6, 2.15, 0.16, 0.025), bodyMat, [0, 0, 0], [0, 0, 0], {
      isBody: true,
      withEdges: true,
    });
    addPart(rec, new THREE.BoxGeometry(2.3, 0.06, 1.85), matRecess, [0, 0.14, 0]);

    TECHNIQUES_17_WEIGHTS.forEach((weight, idx) => {
      const col = idx % 6;
      const row = Math.floor(idx / 6);
      const fx = -0.88 + col * 0.35;
      const fz = -0.48 + row * 0.48;
      const finH = 0.35 + (weight / 100) * 1.15;
      const finMat = weight >= 90 ? rustMat : weight >= 65 ? amberMat : watchMat;

      const finGroup = new THREE.Group();
      finGroup.position.set(fx, 0.16, fz);
      rec.root.add(finGroup);

      addPart(rec, createChamferedBox(0.18, 0.3, finH, 0.01), bodyMat, [0, 0, 0], [0, 0, 0], {
        isBody: true,
        withEdges: true,
      }, finGroup);
      addPart(rec, new THREE.BoxGeometry(0.13, 0.1, 0.26), finMat, [0, finH - 0.06, 0], [0, 0, 0], {
        isAccent: true,
      }, finGroup);
      animHandles.permFins.push({ group: finGroup, idx });
    });
  }

  // =========================================================================
  // 4. INSPECTION GATE (Center Portal / Archway + Status Ring)
  // =========================================================================
  {
    const rec = registerNode(NODE_ANCHORS.inspectionGate, [2.3, 3.0, 1.7]);
    const bodyMat = trackM(matSlate.clone());
    const amberMat = makeAccentMat(PALETTE.amber);

    addPart(rec, createChamferedBox(2.2, 1.45, 0.18, 0.03), bodyMat, [0, 0, 0], [0, 0, 0], {
      isBody: true,
      withEdges: true,
    });
    [-0.75, 0.75].forEach((px) => {
      addPart(rec, createChamferedBox(0.34, 0.74, 1.88, 0.025), bodyMat, [px, 0.18, 0], [0, 0, 0], {
        isBody: true,
        withEdges: true,
      });
    });
    addPart(rec, createChamferedBox(2.0, 0.8, 0.32, 0.03), bodyMat, [0, 2.04, 0], [0, 0, 0], {
      isBody: true,
      withEdges: true,
    });
    addPart(rec, new THREE.TorusGeometry(0.26, 0.042, 14, 32), matTrimMetal, [0, 2.54, 0]);
    addPart(rec, new THREE.CylinderGeometry(0.16, 0.16, 0.07, 24), amberMat, [0, 2.54, 0], [Math.PI / 2, 0, 0], {
      isAccent: true,
    });
  }

  // =========================================================================
  // 5. DNS / MAIL / TLS STACK (Center-Right)
  // =========================================================================
  {
    const rec = registerNode(NODE_ANCHORS.infraStack, [2.4, 2.7, 2.4]);
    const bodyMat = trackM(matSlate.clone());
    const sageMat = makeAccentMat(PALETTE.sage);

    addPart(rec, createChamferedBox(2.0, 2.0, 0.16, 0.025), bodyMat, [0, 0, 0], [0, 0, 0], {
      isBody: true,
      withEdges: true,
    });
    [
      [-0.72, -0.72],
      [0.72, -0.72],
      [-0.72, 0.72],
      [0.72, 0.72],
    ].forEach(([rx, rz]) => {
      addPart(rec, new THREE.CylinderGeometry(0.035, 0.035, 1.95, 12), matTrimMetal, [rx, 1.12, rz]);
    });
    for (let i = 0; i < 5; i++) {
      const y = 0.24 + i * 0.36;
      const w = 1.66 - i * 0.05;
      addPart(rec, createChamferedBox(w, w, 0.19, 0.02), bodyMat, [0, y, 0], [0, 0, 0], {
        isBody: true,
        withEdges: true,
      });
      addPart(rec, new THREE.BoxGeometry(w * 0.58, 0.03, 0.05), sageMat, [0, y + 0.095, w / 2 + 0.01], [0, 0, 0], {
        isAccent: true,
      });
    }
    animHandles.infraRing = addPart(
      rec,
      new THREE.TorusGeometry(1.08, 0.025, 12, 48),
      matTrimMetal,
      [0, 1.25, 0],
      [Math.PI / 2, 0, 0]
    );
  }

  // =========================================================================
  // 6. IP / ASN / GEO RELAY TOWER (Back-Right)
  // =========================================================================
  {
    const rec = registerNode(NODE_ANCHORS.relayTower, [2.0, 3.2, 2.0]);
    const bodyMat = trackM(matSlate.clone());
    const watchMat = makeAccentMat(PALETTE.watch);

    addPart(rec, new THREE.CylinderGeometry(0.72, 0.8, 0.2, 24), bodyMat, [0, 0.1, 0], [0, 0, 0], {
      isBody: true,
      withEdges: true,
    });
    addPart(rec, new THREE.CylinderGeometry(0.17, 0.28, 2.45, 16), bodyMat, [0, 1.42, 0], [0, 0, 0], {
      isBody: true,
      withEdges: true,
    });
    for (let i = 0; i < 3; i++) {
      const a = (i / 3) * Math.PI * 2;
      addPart(
        rec,
        createChamferedBox(0.08, 0.52, 1.05, 0.012),
        matTrimMetal,
        [Math.sin(a) * 0.34, 0.2, Math.cos(a) * 0.34],
        [0, a, 0]
      );
    }
    [1.05, 1.72, 2.38].forEach((ry, idx) => {
      addPart(rec, new THREE.CylinderGeometry(0.4 - idx * 0.06, 0.4 - idx * 0.06, 0.06, 24), matTrimMetal, [0, ry, 0]);
    });
    animHandles.relaySweepRing = addPart(
      rec,
      new THREE.TorusGeometry(0.46, 0.026, 12, 36),
      watchMat,
      [0, 1.45, 0],
      [Math.PI / 2, 0, 0],
      { isAccent: true }
    );
  }

  // =========================================================================
  // 7. TWIN STATE VAULTS — Baseline (Slate Blue) vs. Drift / PreCrime (Violet/Rust)
  // =========================================================================
  {
    const rec = registerNode(NODE_ANCHORS.twinVaults, [2.7, 2.8, 2.6]);
    const bodyMat = trackM(matSlate.clone());
    const baselineMat = makeAccentMat(PALETTE.slateBlue);
    const driftMat = makeAccentMat(PALETTE.mutedViolet);
    animHandles.driftFlagMat = driftMat;

    addPart(rec, createChamferedBox(2.4, 2.4, 0.16, 0.03), bodyMat, [0, 0, 0], [0, 0, 0], {
      isBody: true,
      withEdges: true,
    });
    for (let b = 0; b < 4; b++) {
      const y = 0.24 + b * 0.4;
      addPart(rec, createChamferedBox(1.8, 0.82, 0.25, 0.02), bodyMat, [0, y, -0.56], [0, 0, 0], {
        isBody: true,
        withEdges: true,
      });
      addPart(rec, new THREE.BoxGeometry(1.36, 0.04, 0.05), baselineMat, [0, y + 0.125, -0.13], [0, 0, 0], {
        isAccent: true,
      });
    }

    const driftGroup = new THREE.Group();
    driftGroup.position.set(0, 0.24, 0.56);
    rec.root.add(driftGroup);
    animHandles.driftStackGroup = driftGroup;

    for (let b = 0; b < 4; b++) {
      const y = b * 0.4;
      addPart(rec, createChamferedBox(1.8, 0.82, 0.25, 0.02), bodyMat, [0, y, 0], [0, 0, 0], {
        isBody: true,
        withEdges: true,
      }, driftGroup);
      addPart(rec, new THREE.BoxGeometry(1.36, 0.04, 0.05), driftMat, [0, y + 0.125, 0.42], [0, 0, 0], {
        isAccent: true,
      }, driftGroup);
    }
  }

  // =========================================================================
  // 8. OSINT & RESPONSE HUB (Front-Right on Slab)
  // =========================================================================
  {
    const rec = registerNode(NODE_ANCHORS.responseConsole, [2.5, 2.1, 2.1]);
    const bodyMat = trackM(matSlate.clone());

    addPart(rec, createChamferedBox(2.35, 1.9, 0.16, 0.025), bodyMat, [0, 0, 0], [0, 0, 0], {
      isBody: true,
      withEdges: true,
    });
    addPart(rec, createChamferedBox(2.0, 1.55, 1.05, 0.03), bodyMat, [0, 0.16, 0], [0, 0, 0], {
      isBody: true,
      withEdges: true,
    });
    // 4 recessed OSINT intake bays on top deck
    [
      [-0.48, -0.36],
      [0.48, -0.36],
      [-0.48, 0.36],
      [0.48, 0.36],
    ].forEach(([bx, bz], idx) => {
      addPart(rec, createRecessedFrame(0.76, 0.58, 0.54, 0.38, 0.14, 0.015), matTrimMetal, [bx, 1.21, bz]);
      const bayMat = makeAccentMat(idx < 2 ? PALETTE.sage : PALETTE.amber);
      addPart(rec, new THREE.BoxGeometry(0.46, 0.05, 0.06), bayMat, [bx, 1.36, bz + 0.26], [0, 0, 0], {
        isAccent: true,
      });
      animHandles.osintBayMats.push(bayMat);
    });
    // Dual Takedown & MISP output ports on front face
    const amberPort = makeAccentMat(PALETTE.amber);
    const sagePort = makeAccentMat(PALETTE.sage);
    addPart(rec, new THREE.BoxGeometry(0.62, 0.12, 0.08), sagePort, [-0.48, 0.72, 0.78], [0, 0, 0], {
      isAccent: true,
    });
    addPart(rec, new THREE.BoxGeometry(0.62, 0.12, 0.08), amberPort, [0.48, 0.72, 0.78], [0, 0, 0], {
      isAccent: true,
    });
  }

  // =========================================================================
  // DIRECTIONAL ARCS WITH ORIENTED ARROWHEADS & SEQUENTIAL PACKETS
  // =========================================================================
  const ARC_SPECS = [
    {
      id: 'arc-brand-rack',
      color: PALETTE.amber,
      pts: [
        [-6.6, 1.15, -2.1],
        [-6.55, 1.9, -0.25],
        [-6.0, 1.0, 1.55],
      ],
    },
    {
      id: 'arc-rack-actor',
      color: PALETTE.amber,
      pts: [
        [-6.0, 1.0, 1.55],
        [-4.3, 1.85, 2.05],
        [-2.6, 0.95, 2.3],
      ],
    },
    {
      id: 'arc-actor-gate-pass',
      color: PALETTE.amber,
      pts: [
        [-2.6, 0.95, 2.3],
        [-1.5, 2.05, 1.25],
        [-0.2, 1.15, 0.0],
      ],
    },
    {
      id: 'arc-actor-gate-drop',
      color: PALETTE.rust,
      pts: [
        [-2.4, 0.65, 2.3],
        [-1.9, 1.05, 1.45],
        [-1.15, 0.42, 0.65],
      ],
    },
    {
      id: 'arc-gate-infra',
      color: PALETTE.amber,
      pts: [
        [-0.2, 1.15, 0.0],
        [1.4, 2.1, -1.0],
        [3.0, 1.15, -1.9],
      ],
    },
    {
      id: 'arc-infra-relay',
      color: PALETTE.watch,
      pts: [
        [3.0, 1.25, -1.9],
        [4.5, 2.15, -2.25],
        [6.0, 1.35, -2.5],
      ],
    },
    {
      id: 'arc-infra-vault-base',
      color: PALETTE.slateBlue,
      pts: [
        [3.0, 1.05, -1.9],
        [5.05, 1.85, -0.8],
        [7.1, 1.05, 0.15],
      ],
    },
    {
      id: 'arc-infra-vault-drift',
      color: PALETTE.rust,
      pts: [
        [3.0, 1.25, -1.9],
        [5.05, 2.15, -0.35],
        [7.1, 1.25, 1.25],
      ],
    },
    {
      id: 'arc-vault-response',
      color: PALETTE.amber,
      pts: [
        [7.1, 1.1, 0.85],
        [5.55, 1.95, 2.05],
        [3.6, 1.1, 2.8],
      ],
    },
  ];

  const arcs = new Map();
  const dotSphereGeo = trackG(new THREE.SphereGeometry(0.036, 8, 8));
  const arrowHeadGeo = trackG(new THREE.ConeGeometry(0.11, 0.30, 12));
  const pulseGeo = trackG(new THREE.ConeGeometry(0.095, 0.25, 10));

  ARC_SPECS.forEach((spec) => {
    const curve = new THREE.CatmullRomCurve3(spec.pts.map((p) => new THREE.Vector3(...p)));
    const dotCount = 24;
    const dotMat = trackM(
      new THREE.MeshStandardMaterial({
        color: spec.color,
        roughness: 0.35,
        metalness: 0.3,
        emissive: new THREE.Color(spec.color),
        emissiveIntensity: 0.22,
        transparent: true,
        opacity: 0.82,
      })
    );
    const instancedDots = new THREE.InstancedMesh(dotSphereGeo, dotMat, dotCount);
    instancedDots.frustumCulled = false;
    const dummy = new THREE.Object3D();
    for (let i = 0; i < dotCount; i++) {
      // Stop dots cleanly just behind the terminal arrowhead at 0.90
      const u = (i / (dotCount - 1)) * 0.88;
      curve.getPointAt(u, _vA);
      dummy.position.copy(_vA);
      dummy.updateMatrix();
      instancedDots.setMatrixAt(i, dummy.matrix);
    }
    instancedDots.instanceMatrix.needsUpdate = true;
    scene.add(instancedDots);

    // Fixed terminal directional arrowhead oriented strictly along forward tangent
    const arrowMat = trackM(
      new THREE.MeshStandardMaterial({
        color: spec.color,
        roughness: 0.3,
        metalness: 0.4,
        emissive: new THREE.Color(spec.color),
        emissiveIntensity: 0.28,
        transparent: true,
        opacity: 0.92,
      })
    );
    const arrowHead = new THREE.Mesh(arrowHeadGeo, arrowMat);
    curve.getPointAt(0.91, _vA);
    curve.getTangentAt(0.91, _vB).normalize();
    arrowHead.position.copy(_vA);
    arrowHead.quaternion.setFromUnitVectors(_up, _vB);
    scene.add(arrowHead);

    const pulseMat = trackM(
      new THREE.MeshStandardMaterial({
        color: 0xeceee7,
        roughness: 0.22,
        metalness: 0.3,
        emissive: new THREE.Color(spec.color),
        emissiveIntensity: 0.55,
      })
    );
    const pulseMesh = new THREE.Mesh(pulseGeo, pulseMat);
    pulseMesh.visible = false;
    scene.add(pulseMesh);

    arcs.set(spec.id, {
      id: spec.id,
      curve,
      instancedDots,
      dotMat,
      arrowHead,
      arrowMat,
      pulseMesh,
      baseColor: new THREE.Color(spec.color),
      dimColor: new THREE.Color(PALETTE.arcDim),
      activeWeight: 1,
      packetT: 0.5,
      packetVisible: false,
    });
  });

  // =========================================================================
  // STEP CONTROL & LAYER-1 CLICK
  // =========================================================================
  function setStep(index, focusCamera = true) {
    currentStepIndex = Math.max(0, Math.min(WALKTHROUGH_STEPS.length - 1, index));
    stepElapsed = 0;
    if (focusCamera) {
      const s = WALKTHROUGH_STEPS[currentStepIndex];
      targetCamPos.set(...s.camera.position);
      targetLookAt.set(...s.camera.target);
      camTransition = true;
    }
    requestRender();
  }

  function playScrollEntrance(stepIdx = currentStepIndex) {
    currentStepIndex = Math.max(0, Math.min(WALKTHROUGH_STEPS.length - 1, stepIdx));
    stepElapsed = 0;
    const s = WALKTHROUGH_STEPS[currentStepIndex];
    camera.position.set(s.camera.position[0] - 4.5, s.camera.position[1] + 5.5, s.camera.position[2] + 6.5);
    controls.target.set(0, 0, 0);
    controls.update();
    targetCamPos.set(...s.camera.position);
    targetLookAt.set(...s.camera.target);
    camTransition = true;
    clock.getDelta();
    requestRender();
  }

  const raycaster = new THREE.Raycaster();
  raycaster.layers.set(1);
  const pointer = new THREE.Vector2();
  let downXY = { x: 0, y: 0 };

  function onPointerDown(e) {
    downXY = { x: e.clientX, y: e.clientY };
  }
  function onPointerUp(e) {
    if (Math.hypot(e.clientX - downXY.x, e.clientY - downXY.y) > 6) return;
    const rect = renderer.domElement.getBoundingClientRect();
    pointer.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
    pointer.y = -((e.clientY - rect.top) / rect.height) * 2 + 1;
    raycaster.setFromCamera(pointer, camera);
    const hits = raycaster.intersectObjects(hitProxies, false);
    if (hits.length > 0) {
      const nodeId = hits[0].object.userData.nodeId;
      if (nodeId) callbacks.onSelectNode(nodeId);
    }
  }
  renderer.domElement.addEventListener('pointerdown', onPointerDown);
  renderer.domElement.addEventListener('pointerup', onPointerUp);

  // =========================================================================
  // RENDER LOOP & PROJECTION (NODE LABELS + TRAVELING URL PACKETS)
  // =========================================================================
  let disposed = false;
  let frameId = 0;
  let loopQueued = false;
  let isVisible = true;
  const clock = new THREE.Clock();

  function afterDraw(cb) {
    if (disposed) return;
    const gl = renderer.getContext();
    const sync = gl && gl.fenceSync ? gl.fenceSync(gl.SYNC_GPU_COMMANDS_COMPLETE, 0) : null;
    if (sync && gl.flush) {
      gl.flush();
      const poll = () => {
        if (disposed) return;
        const status = gl.getSyncParameter(sync, gl.SYNC_STATUS);
        if (status === gl.UNSIGNALED) frameId = window.setTimeout(poll, 4);
        else {
          gl.deleteSync(sync);
          frameId = window.setTimeout(cb, 16);
        }
      };
      frameId = window.setTimeout(poll, 4);
    } else {
      frameId = window.setTimeout(cb, 20);
    }
  }

  function projectOverlayCoords() {
    const stepDef = WALKTHROUGH_STEPS[currentStepIndex];
    const rect = renderer.domElement.getBoundingClientRect();
    const nodeCoords = {};
    const packetCoords = {};

    stepDef.activeNodes.forEach((nodeId) => {
      const rec = nodes.get(nodeId);
      if (!rec) return;
      _vA.set(
        rec.anchor.position[0],
        rec.root.position.y + rec.anchor.labelHeight,
        rec.anchor.position[2]
      );
      _vA.project(camera);
      const x = Math.round(((_vA.x + 1) * 0.5) * rect.width);
      const y = Math.round(((-_vA.y + 1) * 0.5) * rect.height);
      const visible =
        _vA.z > -1 && _vA.z < 1 && x > -40 && x < rect.width + 40 && y > -20 && y < rect.height + 20;
      nodeCoords[nodeId] = { x, y, visible };
    });

    stepDef.activeArcs.forEach((arcId) => {
      const arc = arcs.get(arcId);
      if (!arc || !arc.packetVisible) {
        packetCoords[arcId] = { x: 0, y: 0, visible: false };
        return;
      }
      arc.curve.getPointAt(arc.packetT, _vA);
      _vA.y += 0.28;
      _vA.project(camera);
      const x = Math.round(((_vA.x + 1) * 0.5) * rect.width);
      const y = Math.round(((-_vA.y + 1) * 0.5) * rect.height);
      const visible =
        _vA.z > -1 && _vA.z < 1 && x > 40 && x < rect.width - 40 && y > 65 && y < rect.height - 70;
      packetCoords[arcId] = { x, y, visible };
    });

    callbacks.onFrameProject(nodeCoords, packetCoords);
  }

  function stepScene(delta) {
    stepElapsed += delta;
    const stepDef = WALKTHROUGH_STEPS[currentStepIndex];
    const activeNodes = new Set(stepDef.activeNodes);
    const activeArcs = new Set(stepDef.activeArcs);
    const packetDefs = stepDef.routePackets(BRAND_PROFILES['pashabank.az']);
    const packetDefByArc = new Map(packetDefs.map((p) => [p.arcId, p]));

    if (camTransition) {
      const k = 5.5;
      camera.position.x = THREE.MathUtils.damp(camera.position.x, targetCamPos.x, k, delta);
      camera.position.y = THREE.MathUtils.damp(camera.position.y, targetCamPos.y, k, delta);
      camera.position.z = THREE.MathUtils.damp(camera.position.z, targetCamPos.z, k, delta);
      controls.target.x = THREE.MathUtils.damp(controls.target.x, targetLookAt.x, k, delta);
      controls.target.y = THREE.MathUtils.damp(controls.target.y, targetLookAt.y, k, delta);
      controls.target.z = THREE.MathUtils.damp(controls.target.z, targetLookAt.z, k, delta);
      if (
        camera.position.distanceToSquared(targetCamPos) < 0.002 &&
        controls.target.distanceToSquared(targetLookAt) < 0.002
      ) {
        camTransition = false;
      }
    }
    controls.update();

    nodes.forEach((rec) => {
      const isActive = activeNodes.has(rec.anchor.id);
      const targetW = isActive ? 1.0 : 0.16;
      rec.activeWeight = THREE.MathUtils.damp(rec.activeWeight, targetW, 7.0, delta);

      rec.bodyMats.forEach((m) => {
        m.color.copy(_dimBodyColor).lerp(_activeBodyColor, rec.activeWeight);
      });
      rec.edgeMats.forEach((em) => {
        em.opacity = THREE.MathUtils.lerp(0.24, 0.92, rec.activeWeight);
      });
      rec.accentMats.forEach((am) => {
        const base = rec.baseEmissives.get(am) ?? 0.18;
        am.emissiveIntensity = base * THREE.MathUtils.lerp(0.1, 1.55, rec.activeWeight);
      });
    });

    // Step-driven hardware animations
    if (animHandles.brandBeacon && !prefersReducedMotion && activeNodes.has('brandHQ')) {
      animHandles.brandBeacon.rotation.y += delta * 0.4;
    }
    animHandles.permFins.forEach((fin) => {
      let targetScaleY = 1.0;
      if (currentStepIndex === 1 && !prefersReducedMotion) {
        targetScaleY = Math.max(0.2, Math.min(1.0, (stepElapsed - fin.idx * 0.05) * 2.2));
      }
      fin.group.scale.y = THREE.MathUtils.damp(fin.group.scale.y, targetScaleY, 8.0, delta);
    });
    if (animHandles.infraRing && !prefersReducedMotion && activeNodes.has('infraStack')) {
      animHandles.infraRing.rotation.z += delta * 0.25;
    }
    if (animHandles.relaySweepRing && activeNodes.has('relayTower')) {
      const targetRingY = prefersReducedMotion
        ? 1.45
        : 1.45 + Math.sin(stepElapsed * 1.8) * 0.68;
      animHandles.relaySweepRing.position.y = THREE.MathUtils.damp(
        animHandles.relaySweepRing.position.y,
        targetRingY,
        6.0,
        delta
      );
    }
    if (animHandles.driftStackGroup && animHandles.driftFlagMat) {
      const isDriftStep = currentStepIndex === 5;
      const targetY = isDriftStep ? 0.52 : 0.24;
      animHandles.driftStackGroup.position.y = THREE.MathUtils.damp(
        animHandles.driftStackGroup.position.y,
        targetY,
        4.5,
        delta
      );
      _colorA.setHex(isDriftStep ? PALETTE.rust : PALETTE.mutedViolet);
      animHandles.driftFlagMat.color.lerp(_colorA, Math.min(1, delta * 5));
      animHandles.driftFlagMat.emissive.lerp(_colorA, Math.min(1, delta * 5));
    }
    animHandles.osintBayMats.forEach((bMat, idx) => {
      if (currentStepIndex === 6 && !prefersReducedMotion) {
        const phase = (stepElapsed * 1.4) % 4;
        bMat.emissiveIntensity = Math.abs(phase - idx) < 0.85 ? 0.58 : 0.16;
      }
    });

    // Sequential forward pipeline & non-looping drop timing
    const pipelineArcs = stepDef.activeArcs.filter(
      (id) => packetDefByArc.get(id)?.kind !== 'drop'
    );
    const legDuration = 1.65;
    const dwellDuration = 1.55;
    const totalCycle = Math.max(legDuration, pipelineArcs.length * legDuration + dwellDuration);
    const cycleTime = prefersReducedMotion
      ? pipelineArcs.length * legDuration
      : stepElapsed % totalCycle;

    arcs.forEach((arc) => {
      const isActive = activeArcs.has(arc.id);
      const targetW = isActive ? 1.0 : 0.08;
      arc.activeWeight = THREE.MathUtils.damp(arc.activeWeight, targetW, 7.0, delta);

      arc.dotMat.opacity = THREE.MathUtils.lerp(0.11, 0.9, arc.activeWeight);
      arc.dotMat.color.copy(arc.dimColor).lerp(arc.baseColor, arc.activeWeight);
      arc.dotMat.emissiveIntensity = isActive ? 0.35 : 0.01;

      arc.arrowMat.opacity = THREE.MathUtils.lerp(0.14, 0.95, arc.activeWeight);
      arc.arrowMat.color.copy(arc.dimColor).lerp(arc.baseColor, arc.activeWeight);
      arc.arrowMat.emissiveIntensity = isActive ? 0.42 : 0.01;

      if (!isActive) {
        arc.pulseMesh.visible = false;
        arc.packetVisible = false;
        return;
      }

      const pktDef = packetDefByArc.get(arc.id);
      if (pktDef?.kind === 'drop') {
        // One-way forward transit to the gate drop stop; never re-emits from origin
        const dropProgress = prefersReducedMotion ? 1 : Math.min(1, stepElapsed / 1.3);
        const t = 0.08 + 0.78 * easeInOutCubic(dropProgress);
        arc.packetT = t;
        arc.packetVisible = true;
        arc.pulseMesh.visible = !prefersReducedMotion && dropProgress < 1;
      } else {
        const legIdx = pipelineArcs.indexOf(arc.id);
        const legStart = legIdx * legDuration;
        const legEnd = (legIdx + 1) * legDuration;
        const nextArcId = pipelineArcs[legIdx + 1];
        const nextIsHandoff = nextArcId && packetDefByArc.get(nextArcId)?.kind === 'handoff';

        if (cycleTime < legStart) {
          // Waiting upstream; keep hidden so packets never bunch at origin
          arc.packetT = 0.08;
          arc.packetVisible = false;
          arc.pulseMesh.visible = false;
        } else if (cycleTime < legEnd) {
          // Actively gliding forward from source to target
          const u = (cycleTime - legStart) / legDuration;
          arc.packetT = 0.08 + 0.78 * easeInOutCubic(u);
          arc.packetVisible = true;
          arc.pulseMesh.visible = !prefersReducedMotion;
        } else {
          // Arrived cleanly at target; hand off if next leg continues same domain
          arc.packetT = 0.84;
          arc.packetVisible = !nextIsHandoff;
          arc.pulseMesh.visible = false;
        }
      }

      if (arc.pulseMesh.visible) {
        arc.curve.getPointAt(arc.packetT, _vA);
        arc.curve.getTangentAt(arc.packetT, _vB).normalize();
        arc.pulseMesh.position.copy(_vA);
        _qA.setFromUnitVectors(_up, _vB);
        arc.pulseMesh.quaternion.copy(_qA);
      }
    });
  }

  function requestRender() {
    if (disposed || loopQueued) return;
    loopQueued = true;
    frameId = requestAnimationFrame(tick);
  }

  function tick() {
    loopQueued = false;
    if (disposed) return;
    const delta = Math.min(0.033, clock.getDelta());
    stepScene(delta);
    if (isVisible) {
      renderer.render(scene, camera);
      projectOverlayCoords();
    }

    if (isVisible && (!prefersReducedMotion || camTransition)) {
      if (isSoftwareGl) {
        afterDraw(() => {
          if (!disposed) requestRender();
        });
      } else {
        requestRender();
      }
    }
  }

  if (!isSoftwareGl) renderer.compile(scene, camera);
  stepScene(0.016);
  renderer.render(scene, camera);
  projectOverlayCoords();
  if (!prefersReducedMotion) requestRender();

  const resizeObserver = new ResizeObserver((entries) => {
    for (const entry of entries) {
      const w = Math.max(320, Math.floor(entry.contentRect.width));
      const h = Math.max(320, Math.floor(entry.contentRect.height));
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h);
      requestRender();
    }
  });
  resizeObserver.observe(mountEl);

  const intersectionObserver = new IntersectionObserver((entries) => {
    isVisible = entries[0]?.isIntersecting ?? true;
    if (isVisible) {
      clock.getDelta();
      requestRender();
    }
  });
  intersectionObserver.observe(mountEl);

  function onContextLost(e) {
    e.preventDefault();
    cancelAnimationFrame(frameId);
    clearTimeout(frameId);
  }
  function onContextRestored() {
    requestRender();
  }
  renderer.domElement.addEventListener('webglcontextlost', onContextLost);
  renderer.domElement.addEventListener('webglcontextrestored', onContextRestored);

  return {
    setStep,
    playScrollEntrance,
    dispose() {
      disposed = true;
      cancelAnimationFrame(frameId);
      clearTimeout(frameId);
      resizeObserver.disconnect();
      intersectionObserver.disconnect();
      controls.dispose();
      renderer.domElement.removeEventListener('pointerdown', onPointerDown);
      renderer.domElement.removeEventListener('pointerup', onPointerUp);
      renderer.domElement.removeEventListener('webglcontextlost', onContextLost);
      renderer.domElement.removeEventListener('webglcontextrestored', onContextRestored);
      geos.forEach((g) => g.dispose());
      mats.forEach((m) => m.dispose());
      texs.forEach((t) => t.dispose());
      envTex.dispose();
      renderer.dispose();
      if (renderer.domElement.parentNode === mountEl) {
        mountEl.removeChild(renderer.domElement);
      }
    },
  };
}
