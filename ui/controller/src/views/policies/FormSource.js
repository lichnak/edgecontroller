// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019-2020 Intel Corporation

import React from 'react';
import PropTypes from 'prop-types';
import { withStyles } from '@material-ui/core/styles';
import TextField from '@material-ui/core/TextField';
import Typography from '@material-ui/core/Typography';
import Button from '@material-ui/core/Button';

const styles = theme => ({
  container: {
    display: 'flex',
    flexWrap: 'wrap',
  },
  textField: {
    marginLeft: theme.spacing(),
    marginRight: theme.spacing(),
    width: 200,
  },
  fieldSet: {
    width: "100%",
  },
  dense: {
    marginTop: 19,
  },
  menu: {
    width: 200,
  },
  spacer: {
    width: "100%",
    padding: 20,
  }
});


class SourceForm extends React.Component {

  handleChange = name => event => {
    this.setState({ [name]: event.target.value });
  };

  render() {
    const { classes } = this.props;

    return (
      <form className={classes.container} noValidate autoComplete="off">
        <Typography variant="h6" className={classes.fieldSet} gutterBottom>
          Mac Filter
        </Typography>
                
        <TextField
          required
          id="standard-name"
          label="Filter"
          className={classes.textField}
          margin="normal"
        />

        <div className={classes.spacer}></div>

        <Typography variant="h6" className={classes.fieldSet} gutterBottom>
          IP Filter
        </Typography>

        <TextField
          required
          id="standard-type"
          label="Address"
          className={classes.textField}
          margin="normal"
        />

        <TextField
          required
          id="standard-host"
          label="Mask"
          className={classes.textField}
          margin="normal"
        />

        <TextField
          required
          id="standard-error"
          label="Begin Port"
          className={classes.textField}
          margin="normal"
        />

        <TextField
          required
          id="standard-error"
          label="End Port"
          className={classes.textField}
          margin="normal"
        />

        <div className={classes.spacer}></div>

        <TextField
          required
          id="standard-error"
          label="Protocol"
          className={classes.textField}
          margin="normal"
        />

        <div className={classes.spacer}></div>

        <Typography variant="h6" className={classes.fieldSet} gutterBottom>
          GTP Filter
        </Typography>
                
        <TextField
          id="standard-name"
          label="Address"
          className={classes.textField}
          onChange={this.handleChange('name')}
          margin="normal"
        />

        <TextField
          id="standard-name"
          label="Mask"
          className={classes.textField}
          onChange={this.handleChange('name')}
          margin="normal"
        />
        
        <TextField
          id="standard-name"
          label="IMSIS"
          className={classes.textField}
          onChange={this.handleChange('name')}
          margin="normal"
        />

        <div className={classes.spacer}></div>

        <Button variant="contained" color="secondary" className={classes.button}>
          Submit
        </Button>
      </form>
    );
  }
}

SourceForm.propTypes = {
  classes: PropTypes.object.isRequired,
};

export default withStyles(styles)(SourceForm);
