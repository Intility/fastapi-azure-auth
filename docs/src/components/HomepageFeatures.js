import React from 'react'
import clsx from 'clsx'
import styles from './HomepageFeatures.module.css'

import Link from '@docusaurus/Link'

const FeatureList = [
  {
    title: 'Single-tenant',
    img: '../../static/img/global/fastad.png',
    href: '/single-tenant',
    description: (
      <>
        Full tutorial on how to set-up Azure AD for a <b>single-tenant</b> application, and how to configure
        FastAPI-Azure-Auth
      </>
    ),
  },
  {
    title: 'Multi-tenant',
    img: '../../static/img/global/fastadmultitenant.png',
    href: '/multi-tenant',
    description: (
      <>
        Full tutorial on how to set-up Azure AD for a <b>multi-tenant</b> application, and how to configure
        FastAPI-Azure-Auth
      </>
    ),
  },
]

function Feature({ id, img = 'div', title, href, description }) {
  return (
    <div
      className={clsx('col col--4', {
        'col--offset-2': FeatureList.length === 2 && !id,
      })}
    >
      <Link to={href}>
        <div className="text--center">
          <img src={img} className={styles.featureSvg} alt={title} />
        </div>
      </Link>
      <div className="text--center padding-horiz--md">
        <h3>
          <Link to={href}>{title}</Link>
        </h3>
        <p>{description}</p>
      </div>
    </div>
  );
}

export default function HomepageFeatures() {
  return (
    <section className={styles.features}>
      <div className="container">
        <div className="row">
          {FeatureList.map((props, idx) => (
            <Feature key={idx} id={idx} {...props} />
          ))}
        </div>
      </div>
    </section>
  );
}
