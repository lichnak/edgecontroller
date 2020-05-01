// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019-2020 Intel Corporation

import React, { Component } from 'react';
import withStyles from '@material-ui/core/styles/withStyles';
import Button from '@material-ui/core/Button';

const styles = theme => ({
  primary: {
    marginRight: theme.spacing(2)
  },
  secondary: {
    background: theme.palette.secondary['100'],
    color: 'white'
  },
  spaceTop: {
    marginTop: 20
  }
});

class ButtonBar extends Component {
  constructor(props) {
    super(props);
    this.handlePrimaryAction = this.handlePrimaryAction.bind(this);
  }

  handlePrimaryAction(e) {
    this.props.primaryButtonAction(e);
  }

  render() {
    const {
      classes,
      primaryButtonName,
      secondaryButtonName,
      primaryLink,
      secondaryLink
    } = this.props;

    return (
      <div className={classes.spaceTop}>
        <Button
          className={classes.primary}
          component={primaryLink}
          onClick={this.handlePrimaryAction}
        >
          {primaryButtonName}
        </Button>
        <Button
          variant="contained"
          color="primary"
          className={classes.secondary}
          component={secondaryLink}
        >
          {secondaryButtonName}
        </Button>
      </div>
    )
  }
}

export default withStyles(styles)(ButtonBar);
